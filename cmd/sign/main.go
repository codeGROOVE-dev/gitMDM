// Package main implements the gitMDM configuration file signing tool.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// ASCII printable character boundary.
	asciiSpace = 32

	// Email context extraction.
	emailContextBefore = 20
	emailContextAfter  = 30

	// File permissions.
	sigFileMode = 0o600
)

var (
	configFile = flag.String("config", "", "Path to config file to sign")
	help       = flag.Bool("help", false, "Show help")
)

func main() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "gitmdm-sign - Sign gitMDM configuration files with Sigstore\n\n")
		fmt.Fprint(os.Stderr, "Usage: gitmdm-sign --config <path-to-file>\n\n")
		fmt.Fprint(os.Stderr, "This tool signs configuration files using Sigstore keyless signing.\n")
		fmt.Fprint(os.Stderr, "Creates a .sig file containing both signature and certificate.\n")
		fmt.Fprint(os.Stderr, "It requires cosign to be installed on your system.\n")
		fmt.Fprint(os.Stderr, "It will open a browser for OIDC authentication.\n\n")
		fmt.Fprint(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr)
		fmt.Fprint(os.Stderr, "To install cosign:\n")
		fmt.Fprint(os.Stderr, "  brew install cosign                     # macOS\n")
		fmt.Fprint(os.Stderr, "  go install github.com/sigstore/cosign/v2/cmd/cosign@latest  # Go\n")
		fmt.Fprint(os.Stderr, "  See https://docs.sigstore.dev/cosign/installation for other platforms\n")
	}
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	if err := signConfig(*configFile); err != nil {
		log.Fatalf("Failed to sign config: %v", err)
	}
}

func signConfig(configPath string) error {
	// Check if config file exists
	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("config file not found: %w", err)
	}

	// Check if cosign is installed
	cosignPath, err := exec.LookPath("cosign")
	if err != nil {
		return errors.New("cosign not found in PATH. Please install cosign: https://docs.sigstore.dev/cosign/installation")
	}

	// Get absolute path
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Create temp files for signature and certificate
	sigPath := absPath + ".sig.tmp"
	certPath := absPath + ".cert.tmp"
	bundlePath := absPath + ".sig"

	// Clean up temp files on exit (errors are ignored as cleanup is best-effort)
	defer func() { _ = os.Remove(sigPath) }()  //nolint:errcheck // Best-effort cleanup
	defer func() { _ = os.Remove(certPath) }() //nolint:errcheck // Best-effort cleanup

	// Build the cosign command arguments
	args := []string{
		"sign-blob",
		absPath,
		"--output-signature", sigPath,
		"--output-certificate", certPath,
	}

	// Show what command we're running
	fmt.Printf("\nExecuting: cosign %s\n\n", strings.Join(args, " "))
	fmt.Println("This will open your browser for authentication.")

	// Run cosign (not exec, since we need to process the output)
	cmd := exec.CommandContext(context.Background(), cosignPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cosign signing failed: %w", err)
	}

	// Read the signature and certificate
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	// Combine into our expected format: signature\n---\ncertificate
	bundleContent := fmt.Sprintf("%s\n---\n%s",
		strings.TrimSpace(string(sigData)),
		strings.TrimSpace(string(certData)))

	// Write the bundle
	if err := os.WriteFile(bundlePath, []byte(bundleContent), sigFileMode); err != nil {
		return fmt.Errorf("failed to write signature bundle: %w", err)
	}

	// Try to parse the certificate to show who signed it
	if certData, err := os.ReadFile(certPath); err == nil {
		showSignerInfo(certData)
	}

	fmt.Printf("\n✓ Signature saved to: %s\n", bundlePath)
	fmt.Println("✓ The signature will be embedded in the agent binary during build")
	fmt.Println("✓ Rebuild the agent to include the signature: make build")
	fmt.Println("")
	fmt.Println("Note: The .sig file is embedded into the binary at compile time.")
	fmt.Println("      External .sig files are only needed for runtime config verification.")

	return nil
}

// showSignerInfo shows basic signer info from the certificate.
func showSignerInfo(certPEM []byte) {
	// Quick scan for provider and email in certificate
	certStr := string(certPEM)

	// Detect provider
	provider := "provider"
	if strings.Contains(certStr, "github.com") {
		provider = "github"
	} else if strings.Contains(certStr, "accounts.google.com") {
		provider = "google"
	}

	// Find email
	if idx := strings.Index(certStr, "@"); idx > 0 {
		// Get a reasonable chunk around the @
		start := max(0, idx-emailContextBefore)
		end := min(idx+emailContextAfter, len(certStr))
		chunk := certStr[start:end]

		// Find @ again in chunk and extract email-like string
		if at := strings.Index(chunk, "@"); at > 0 {
			// Simple extraction: take non-space characters around @
			var builder strings.Builder
			// Collect characters before @ (in reverse order)
			start := at
			for start >= 0 && chunk[start] > asciiSpace {
				start--
			}
			start++
			builder.WriteString(chunk[start : at+1])
			// Collect characters after @
			end := at + 1
			for end < len(chunk) && chunk[end] > asciiSpace {
				end++
			}
			builder.WriteString(chunk[at+1 : end])
			email := builder.String()
			if strings.Contains(email, ".") {
				fmt.Printf("\n✓ Signed by: %s:%s\n", provider, email)
				fmt.Printf("✓ To allow: --signed-by \"%s:%s\"\n", provider, email)
			}
		}
	}
}
