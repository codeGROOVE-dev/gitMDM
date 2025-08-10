package main

import (
	_ "embed"
	"errors"
	"log"
	"strings"
)

const errorPrefix = "[ERROR] "

// Embed the signature file for checks.yaml if it exists
// The signature file is created by running: gitmdm-sign --config cmd/agent/checks.yaml
//
//go:embed checks.yaml.sig
var checksConfigSignature []byte

// verifyEmbeddedConfig verifies the embedded checks.yaml configuration.
func verifyEmbeddedConfig() error {
	// Get allowed signers from config or flags
	var allowedSigners []string
	// First check if we have a saved config with ValidSigners
	if cfg, err := loadConfig(); err == nil && len(cfg.ValidSigners) > 0 {
		allowedSigners = cfg.ValidSigners
		log.Printf("[INFO] Using allowed signers from saved config: %v", allowedSigners)
	} else if *signedBy != "" {
		// Use command-line flag if provided
		allowedSigners = parseAllowedSigners(*signedBy)
		log.Printf("[INFO] Using allowed signers from --signed-by flag: %v", allowedSigners)
	} else {
		// Use default
		allowedSigners = []string{"github:t+github@stromberg.org"}
		log.Print("[INFO] Using default allowed signer: github:t+github@stromberg.org")
	}

	// Check if we have an embedded signature
	if len(checksConfigSignature) == 0 || strings.HasPrefix(string(checksConfigSignature), "# Placeholder") {
		log.Print("[ERROR] ⚠️  Configuration Not Signed")
		log.Print("[ERROR] ")
		log.Print("[ERROR] Sign the configuration:")
		log.Print("[ERROR]   gitmdm-sign --config cmd/agent/checks.yaml")
		log.Print("[ERROR]   make build")
		log.Print("[ERROR] ")
		log.Print("[ERROR] Or skip verification (dev only): --skip-signature-check")
		return errors.New("unsigned configuration")
	}

	// Verify the signature directly using embedded data
	signerEmail, err := verifySignatureBundle(checksConfig, checksConfigSignature, allowedSigners)
	if err != nil {
		// Check if it's an invalid signature (modified file)
		if strings.HasPrefix(err.Error(), "invalid_signature:") {
			signer := strings.TrimPrefix(err.Error(), "invalid_signature:")

			log.Print("[ERROR] ⚠️  Configuration Modified After Signing")
			log.Print(errorPrefix)
			log.Printf("[ERROR] The checks.yaml was changed after being signed by: %s", signer)
			log.Print(errorPrefix)
			log.Print("[ERROR] Re-sign it:")
			log.Print("[ERROR]   gitmdm-sign --config cmd/agent/checks.yaml")
			log.Print("[ERROR]   make build")
			log.Print(errorPrefix)
			log.Print("[ERROR] Or skip verification (dev only): --skip-signature-check")
			return errors.New("configuration security check failed")
		}
		// Check if it's specifically an unauthorized signer
		if strings.Contains(err.Error(), "unauthorized signer") {
			// Extract who actually signed it
			actualSigner := ""
			if idx := strings.Index(err.Error(), ": "); idx > 0 {
				parts := strings.Split(err.Error()[idx+2:], " (")
				if len(parts) > 0 {
					actualSigner = parts[0]
				}
			}

			log.Print("[ERROR] ⚠️  Untrusted Signer")
			log.Print(errorPrefix)
			log.Printf("[ERROR] Signed by: %s", actualSigner)
			log.Printf("[ERROR] Expected: %v", allowedSigners)
			log.Print(errorPrefix)
			log.Printf("[ERROR] To trust: --signed-by \"%s\"", actualSigner)
			log.Print("[ERROR] To skip: --skip-signature-check (dev only)")
		}
		return err
	}

	// Log who signed it
	log.Printf("[INFO] ✅ Configuration signed by: %s", signerEmail)

	return nil
}
