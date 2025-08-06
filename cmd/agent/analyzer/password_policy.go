package analyzer

import "strings"

func analyzePasswordPolicy(output string, osName string, baseCommand string, command string) Result {
	// Look for password policy settings
	hasMaxDays := strings.Contains(output, "pass_max_days")
	hasMinDays := strings.Contains(output, "pass_min_days")
	hasMinLen := strings.Contains(output, "pass_min_len") ||
		strings.Contains(output, "minlen") ||
		strings.Contains(output, "minimum length")
	hasComplexity := strings.Contains(output, "complexity") ||
		strings.Contains(output, "require") ||
		strings.Contains(output, "policy")

	// Count how many policy elements are present
	policyCount := 0
	if hasMaxDays {
		policyCount++
	}
	if hasMinDays {
		policyCount++
	}
	if hasMinLen {
		policyCount++
	}
	if hasComplexity {
		policyCount++
	}

	if policyCount >= 2 {
		return Result{Status: "pass", Description: "Password policy configured"}
	}

	if policyCount == 1 {
		return Result{Status: "fail", Description: "Weak password policy"}
	}

	// Check if no policy
	if strings.Contains(output, "not found") ||
		strings.Contains(output, "not configured") ||
		len(output) < 10 {
		return Result{Status: "fail", Description: "No password policy configured"}
	}

	// Can't access
	if strings.Contains(output, "permission denied") {
		return Result{Status: "n/a", Description: "Cannot access password policy"}
	}

	return Result{Status: "fail", Description: "Insufficient password policy"}
}
