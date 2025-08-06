package analyzer

import "strings"

func analyzeFirewall(output string, exitCode int, osName string, baseCommand string) Result {
	// Command-specific analysis
	if baseCommand == "ufw" {
		// UFW specific analysis
		if strings.Contains(output, "status: active") {
			return Result{Status: "pass", Description: "UFW firewall enabled"}
		}
		if strings.Contains(output, "status: inactive") {
			return Result{Status: "fail", Description: "UFW firewall disabled"}
		}
	} else if baseCommand == "iptables" {
		// iptables specific - look for rules
		if strings.Contains(output, "chain") && !strings.Contains(output, "policy accept") {
			// Has chains defined with non-accept policies
			if strings.Contains(output, "0 rules") {
				return Result{Status: "fail", Description: "iptables has no rules"}
			}
			return Result{Status: "pass", Description: "iptables rules configured"}
		}
	} else if baseCommand == "pfctl" {
		// pf firewall (BSD/macOS)
		if strings.Contains(output, "enabled") || (strings.Contains(output, "status") && strings.Contains(output, "enabled")) {
			return Result{Status: "pass", Description: "pf firewall enabled"}
		}
		if strings.Contains(output, "disabled") {
			return Result{Status: "fail", Description: "pf firewall disabled"}
		}
		// If we see rules, it's likely configured
		if strings.Contains(output, "pass") || strings.Contains(output, "block") {
			return Result{Status: "pass", Description: "pf rules configured"}
		}
	}

	// Look for active firewall indicators
	active := strings.Contains(output, "active") ||
		strings.Contains(output, "enabled") ||
		strings.Contains(output, "running") ||
		strings.Contains(output, "rules") ||
		strings.Contains(output, "chain")

	// Check for explicit disabled state
	disabled := strings.Contains(output, "inactive") ||
		strings.Contains(output, "disabled") ||
		strings.Contains(output, "not running") ||
		strings.Contains(output, "status: off")

	if active && !disabled {
		// Check if there are actual rules
		if strings.Contains(output, "0 rules") {
			return Result{Status: "fail", Description: "Firewall active but no rules configured"}
		}
		return Result{Status: "pass", Description: "Firewall enabled"}
	}

	if disabled {
		return Result{Status: "fail", Description: "Firewall disabled"}
	}

	// Permission issues or not available
	if strings.Contains(output, "permission denied") ||
		strings.Contains(output, "not found") ||
		strings.Contains(output, "not accessible") {
		return Result{Status: "n/a", Description: "Cannot access firewall status"}
	}

	// If we got output but can't determine status
	if len(output) > 10 {
		return Result{Status: "n/a", Description: "Firewall status unclear"}
	}

	return Result{Status: "fail", Description: "Firewall not configured"}
}
