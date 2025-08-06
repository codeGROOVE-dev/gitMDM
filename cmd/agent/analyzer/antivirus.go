package analyzer

import "strings"

func analyzeAntivirus(output string, osName string) Result {
	// For systemctl commands, check if service is active
	if strings.Contains(output, "active") && !strings.Contains(output, "inactive") {
		return Result{Status: "pass", Description: "ClamAV daemon active"}
	}

	// macOS XProtect detection via pgrep
	if osName == "darwin" {
		// XProtect processes typically include XProtectService or similar
		if strings.Contains(output, "xprotect") {
			// Parse pgrep output: "PID processname"
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "xprotect") {
					// Extract process name from "PID processname" format
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						return Result{Status: "pass", Description: "XProtect running"}
					}
					return Result{Status: "pass", Description: "XProtect running"}
				}
			}
		}

		// If XProtect is not found on macOS, it's a failure (should always be running)
		// Only check if this was a pgrep command that returned no results
		if strings.Contains(output, "pgrep") || len(output) < 10 {
			return Result{Status: "fail", Description: "XProtect not running"}
		}

		// For macOS, we only care about XProtect, not third-party AV
		// Return n/a for other commands like ps aux
		return Result{Status: "n/a", Description: "Only XProtect is required for macOS"}
	}

	// For ps output, look for AV processes
	if strings.Contains(output, "ps aux") || strings.Contains(output, "pid") {
		// Parse ps output looking for AV processes
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			lower := strings.ToLower(line)
			// Look for common AV processes
			if (strings.Contains(lower, "clamav") && !strings.Contains(lower, "grep")) ||
				(strings.Contains(lower, "sophos") && !strings.Contains(lower, "grep")) ||
				(strings.Contains(lower, "mcafee") && !strings.Contains(lower, "grep")) ||
				(strings.Contains(lower, "symantec") && !strings.Contains(lower, "grep")) ||
				(strings.Contains(lower, "defender") && !strings.Contains(lower, "grep")) ||
				(strings.Contains(lower, "xprotect") && osName == "darwin") ||
				(strings.Contains(lower, "mrt.app") && osName == "darwin") ||
				strings.Contains(lower, "antivirus") {
				return Result{Status: "pass", Description: "Antivirus process detected"}
			}
		}
	}

	// Windows WMI output
	if strings.Contains(output, "displayname") && strings.Contains(output, "productstate") {
		// If we got WMI output with AV products
		if strings.Contains(output, "defender") ||
			strings.Contains(output, "antivirus") ||
			strings.Contains(output, "mcafee") ||
			strings.Contains(output, "norton") ||
			strings.Contains(output, "sophos") {
			return Result{Status: "pass", Description: "Windows antivirus detected"}
		}
	}

	// No AV is often fine for servers/Linux
	if osName == "linux" || osName == "freebsd" || osName == "openbsd" {
		return Result{Status: "n/a", Description: "Antivirus optional for " + osName}
	}

	// Can't check
	if strings.Contains(output, "permission denied") {
		return Result{Status: "n/a", Description: "Cannot check antivirus status"}
	}

	return Result{Status: "n/a", Description: "Antivirus not detected"}
}
