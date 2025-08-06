package analyzer

import "strings"

func analyzeAppFirewall(output string, exitCode int, osName string, baseCommand string) Result {
	// macOS Application Firewall specific analysis (SOC 2 relevant check)
	if baseCommand == "socketfilterfw" {
		// Check global state - this is the main SOC 2 compliance indicator
		if strings.Contains(output, "firewall is enabled") {
			return Result{Status: "pass", Description: "macOS Application Firewall enabled"}
		}
		if strings.Contains(output, "firewall is disabled") {
			return Result{
				Status:      "fail",
				Description: "macOS Application Firewall disabled",
				Remediation: []string{
					"Open System Settings > Network > Firewall",
					"Click on 'Options...'",
					"Turn on 'Enable Firewall'",
				},
			}
		}
	}

	// Permission issues or not available
	if strings.Contains(output, "permission denied") ||
		strings.Contains(output, "not found") ||
		strings.Contains(output, "command not found") {
		return Result{Status: "n/a", Description: "Cannot access application firewall"}
	}

	return Result{Status: "n/a", Description: "Application firewall status unknown"}
}
