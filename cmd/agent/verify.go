package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const (
	// ASCII character ranges.
	asciiSpace  = 32
	asciiTilde  = 126
	asciiDelete = 127

	// Email length limits (RFC 5321).
	maxEmailLength      = 254
	maxLocalPartLength  = 64
	maxDomainPartLength = 253
)

// verifySignatureBundle verifies config data against a signature bundle.
// This function can be used with both file-based and embedded signatures.
// Returns the signer's identity in provider:identity format on success.
func verifySignatureBundle(configData, sigData []byte, allowedSigners []string) (string, error) {
	if len(configData) == 0 {
		return "", errors.New("config data cannot be empty")
	}
	if len(sigData) == 0 {
		return "", errors.New("signature data cannot be empty")
	}
	if len(allowedSigners) == 0 {
		return "", errors.New("no allowed signers specified")
	}

	// Parse signature bundle (format: base64sig\n---\ncert)
	parts := strings.Split(string(sigData), "\n---\n")
	if len(parts) != 2 {
		return "", errors.New("invalid signature bundle format")
	}

	sigBase64 := strings.TrimSpace(parts[0])
	certData := strings.TrimSpace(parts[1])

	// Decode signature from base64
	signature, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode signature (len=%d): %w", len(sigBase64), err)
	}

	// The certificate might be base64-encoded or already in PEM format
	var block *pem.Block
	block, _ = pem.Decode([]byte(certData))
	if block == nil {
		// Try decoding from base64 first
		certPEM, err := base64.StdEncoding.DecodeString(certData)
		if err != nil {
			return "", fmt.Errorf("certificate is neither valid PEM nor base64: %w", err)
		}
		block, _ = pem.Decode(certPEM)
		if block == nil {
			return "", errors.New("failed to parse certificate PEM after base64 decode")
		}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Security: Verify certificate validity
	// Note: Fulcio certificates are short-lived (typically valid for 10 minutes)
	// We don't check expiration because signatures remain valid after cert expires
	// But we should verify the certificate was valid at signing time
	// For now, we rely on Rekor's transparency log for this validation

	// Extract signer identity and provider from certificate
	signerIdentity, provider := extractSignerInfo(cert)
	if signerIdentity == "" {
		return "", fmt.Errorf("no identity found in certificate (issuer=%s)", cert.Issuer)
	}
	if provider == "" {
		return "", fmt.Errorf("no OIDC provider found in certificate (subject=%s)", cert.Subject)
	}

	// Format as provider:identity
	qualifiedSigner := fmt.Sprintf("%s:%s", provider, signerIdentity)

	// Check if signer is allowed
	allowed := false
	for _, allowedSigner := range allowedSigners {
		// Support both old format (email only) and new format (provider:identity)
		if strings.Contains(allowedSigner, ":") {
			// New format: provider:identity
			if strings.EqualFold(strings.TrimSpace(allowedSigner), strings.TrimSpace(qualifiedSigner)) {
				allowed = true
				break
			}
		} else {
			// Legacy format: just email (for backward compatibility)
			if strings.EqualFold(strings.TrimSpace(allowedSigner), strings.TrimSpace(signerIdentity)) {
				allowed = true
				break
			}
		}
	}

	if !allowed {
		return "", fmt.Errorf("config signed by unauthorized signer: %s (allowed: %v)", qualifiedSigner, allowedSigners)
	}

	// Verify signature using certificate's public key
	hash := sha256.Sum256(configData)

	switch key := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		// ECDSA verification (most common for Sigstore)
		if !ecdsa.VerifyASN1(key, hash[:], signature) {
			return "", fmt.Errorf("invalid_signature:%s", qualifiedSigner)
		}
	case *rsa.PublicKey:
		// RSA verification
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature); err != nil {
			return "", fmt.Errorf("invalid_signature:%s", qualifiedSigner)
		}
	default:
		return "", fmt.Errorf("unsupported public key type: %T", key)
	}

	return qualifiedSigner, nil
}

// extractSignerInfo extracts the signer identity and OIDC provider from a Fulcio certificate.
// Returns (identity, provider) where identity is the email/username and provider is github/google/etc.
func extractSignerInfo(cert *x509.Certificate) (identity string, provider string) {
	var issuer string

	// Extract issuer from Fulcio extension OID 1.3.6.1.4.1.57264.1.1 (issuer)
	// Security: This is a simplified extraction that looks for URLs in the extension
	// A proper implementation would parse the ASN.1 structure, but for Fulcio
	// certificates, this pattern is consistent and safe
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.57264.1.1" {
			issuer = string(ext.Value)
			// Extract HTTPS URL from ASN.1 encoded value
			if idx := strings.Index(issuer, "https://"); idx >= 0 {
				issuer = issuer[idx:]
				// Terminate at first non-printable character
				for i, ch := range issuer {
					if ch < asciiSpace || ch > asciiTilde {
						issuer = issuer[:i]
						break
					}
				}
			}
			break
		}
	}

	// Determine provider from issuer URL
	switch {
	case strings.Contains(issuer, "github.com"):
		provider = "github"
	case strings.Contains(issuer, "accounts.google.com"):
		provider = "google"
	case strings.Contains(issuer, "login.microsoftonline.com"):
		provider = "microsoft"
	case strings.Contains(issuer, "gitlab.com"):
		provider = "gitlab"
	default:
		// Use domain from issuer if unknown
		if issuer != "" {
			if idx := strings.Index(issuer, "://"); idx > 0 {
				domain := issuer[idx+3:]
				if idx := strings.IndexAny(domain, ":/"); idx > 0 {
					domain = domain[:idx]
				}
				provider = domain
			}
		}
	}

	// Extract identity (email or username)
	identity = extractEmailFromCert(cert)

	return identity, provider
}

// extractEmailFromCert extracts email from a Fulcio certificate.
func extractEmailFromCert(cert *x509.Certificate) string {
	// Check Subject Alternative Names first
	for _, email := range cert.EmailAddresses {
		if email != "" && isValidEmail(email) {
			return email
		}
	}

	// Check Fulcio extension OID 1.3.6.1.4.1.57264.1.1 for email
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.57264.1.1" {
			value := string(ext.Value)
			// Simple email extraction: find @ and get surrounding printable chars
			if idx := strings.Index(value, "@"); idx > 0 {
				start, end := idx, idx+1
				// Scan backwards for email start
				for start > 0 && value[start-1] > asciiSpace && value[start-1] < asciiDelete {
					start--
				}
				// Scan forwards for email end
				for end < len(value) && value[end] > asciiSpace && value[end] < asciiDelete {
					end++
				}
				if email := value[start:end]; isValidEmail(email) {
					return email
				}
			}
		}
	}

	return ""
}

// isValidEmail performs basic email validation.
func isValidEmail(email string) bool {
	if len(email) < 3 || len(email) > maxEmailLength {
		return false
	}

	atIdx := strings.LastIndex(email, "@")
	if atIdx <= 0 || atIdx >= len(email)-1 {
		return false
	}

	localPart := email[:atIdx]
	domainPart := email[atIdx+1:]

	if localPart == "" || len(localPart) > maxLocalPartLength {
		return false
	}

	if domainPart == "" || len(domainPart) > maxDomainPartLength {
		return false
	}

	// Must have at least one dot in domain
	if !strings.Contains(domainPart, ".") {
		return false
	}

	return true
}

// parseAllowedSigners parses the comma-separated list of allowed signers.
// Supports both provider:identity format (e.g., "github:username") and legacy email format.
func parseAllowedSigners(signers string) []string {
	if signers == "" {
		return []string{"github:t+github@stromberg.org"}
	}

	parts := strings.Split(signers, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
