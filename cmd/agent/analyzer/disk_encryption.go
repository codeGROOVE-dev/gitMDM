package analyzer

import "strings"

func analyzeDiskEncryption(output string, osName string, baseCommand string) Result {
	// Look for encryption indicators
	encrypted := strings.Contains(output, "crypto") ||
		strings.Contains(output, "luks") ||
		strings.Contains(output, "filevault") ||
		strings.Contains(output, "encrypted") ||
		strings.Contains(output, "bitlocker") ||
		strings.Contains(output, "geli") ||
		strings.Contains(output, "cgd") ||
		strings.Contains(output, "crypto_luks")

	if encrypted {
		return Result{Status: "pass", Description: "Disk encryption enabled"}
	}

	// Check for explicit no encryption
	if strings.Contains(output, "not encrypted") ||
		strings.Contains(output, "encryption: no") ||
		strings.Contains(output, "filevault: off") {
		return Result{Status: "fail", Description: "Disk encryption disabled"}
	}

	// Can't determine
	if strings.Contains(output, "not configured") ||
		strings.Contains(output, "permission denied") ||
		strings.Contains(output, "not found") {
		return Result{Status: "n/a", Description: "Unable to check encryption status"}
	}

	return Result{Status: "fail", Description: "No encryption detected"}
}
