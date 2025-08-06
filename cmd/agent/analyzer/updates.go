package analyzer

import "strings"

func analyzeUpdates(output string, osName string, baseCommand string, exitCode int) Result {
	// Command-specific analysis
	if baseCommand == "apt" {
		// Debian/Ubuntu
		if strings.Contains(output, "0 packages can be upgraded") || strings.Contains(output, "all packages are up to date") {
			return Result{Status: "pass", Description: "APT: System up to date"}
		}
		if strings.Contains(output, "security") {
			return Result{Status: "fail", Description: "APT: Security updates available"}
		}
		if strings.Contains(output, "upgradable") {
			return Result{Status: "fail", Description: "APT: Updates available"}
		}
	} else if baseCommand == "yum" || baseCommand == "dnf" {
		// RHEL/CentOS/Fedora
		if exitCode == 0 && (output == "" || strings.Contains(output, "no packages")) {
			return Result{Status: "pass", Description: "YUM/DNF: System up to date"}
		}
		if strings.Contains(output, "security") {
			return Result{Status: "fail", Description: "YUM/DNF: Security updates available"}
		}
		if exitCode == 100 { // yum/dnf returns 100 when updates are available
			return Result{Status: "fail", Description: "YUM/DNF: Updates available"}
		}
	} else if baseCommand == "softwareupdate" && osName == "darwin" {
		// macOS
		if strings.Contains(output, "no new software available") {
			return Result{Status: "pass", Description: "macOS: System up to date"}
		}
		if strings.Contains(output, "software update found") {
			return Result{
				Status:      "fail",
				Description: "macOS: Updates available",
				Remediation: []string{
					"Open System Settings > General > Software Update",
					"Click 'Update Now' to install available updates",
					"Enable 'Automatic Updates' for security updates",
				},
			}
		}
	} else if baseCommand == "pkg" {
		// FreeBSD/pkg
		if strings.Contains(output, "0 problem(s)") || strings.Contains(output, "no vulnerabilities") {
			return Result{Status: "pass", Description: "pkg: No vulnerabilities"}
		}
		if strings.Contains(output, "vulnerability") || strings.Contains(output, "vulnerabilities") {
			return Result{Status: "fail", Description: "pkg: Vulnerabilities found"}
		}
	}

	// Look for pending updates
	needsUpdates := strings.Contains(output, "upgradable") ||
		strings.Contains(output, "available") ||
		strings.Contains(output, "update") ||
		strings.Contains(output, "security") ||
		strings.Contains(output, "critical")

	// Check if system is up to date
	upToDate := strings.Contains(output, "0 packages") ||
		strings.Contains(output, "no updates") ||
		strings.Contains(output, "up to date") ||
		strings.Contains(output, "current") ||
		strings.Contains(output, "no new")

	if upToDate && !needsUpdates {
		return Result{Status: "pass", Description: "System up to date"}
	}

	// Check for security updates specifically
	if strings.Contains(output, "security") {
		return Result{Status: "fail", Description: "Security updates available"}
	}

	if needsUpdates {
		// Count approximate number of updates
		lines := strings.Split(output, "\n")
		updateCount := 0
		for _, line := range lines {
			if strings.Contains(line, "upgradable") ||
				strings.Contains(line, "update") {
				updateCount++
			}
		}

		if updateCount > 10 {
			return Result{Status: "fail", Description: "Many updates pending"}
		}
		return Result{Status: "fail", Description: "Updates available"}
	}

	// Can't determine
	if strings.Contains(output, "not found") ||
		strings.Contains(output, "permission denied") ||
		len(output) < 5 {
		return Result{Status: "n/a", Description: "Cannot check update status"}
	}

	return Result{Status: "pass", Description: "Updates status checked"}
}
