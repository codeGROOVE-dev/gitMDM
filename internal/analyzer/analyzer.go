// Package analyzer provides generic compliance check analysis based on YAML rules.
package analyzer

import (
	"fmt"
	"gitmdm/internal/config"
	"gitmdm/internal/gitmdm"
	"regexp"
	"strings"
)

// AnalyzeCheck analyzes a CommandOutput against a CommandRule to determine pass/fail.
func AnalyzeCheck(output *gitmdm.CommandOutput, rule config.CommandRule) error {
	// If command/file was skipped or missing, don't fail the check
	if output.Skipped || output.FileMissing {
		return nil // Not a failure, just not applicable
	}

	// Combine stdout and stderr for analysis
	content := output.Stdout + output.Stderr

	// Check includes pattern (fail if ANY line matches - like grep)
	if rule.Includes != "" {
		includesRegex, err := regexp.Compile("(?i)" + rule.Includes)
		if err != nil {
			return fmt.Errorf("invalid includes regex: %w", err)
		}

		// Split content into lines and check each one
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			if includesRegex.MatchString(line) {
				output.Failed = true
				output.FailReason = fmt.Sprintf("Output matched failure pattern: %s", rule.Includes)
				output.Remediation = rule.Remediation
				return nil // Not an error, just a failed check
			}
		}
	}

	// Check excludes pattern (fail if NO line matches - like grep -q)
	if rule.Excludes != "" {
		excludesRegex, err := regexp.Compile("(?i)" + rule.Excludes)
		if err != nil {
			return fmt.Errorf("invalid excludes regex: %w", err)
		}

		// Split content into lines and check if any line matches
		lines := strings.Split(content, "\n")
		matchFound := false
		for _, line := range lines {
			if excludesRegex.MatchString(line) {
				matchFound = true
				break
			}
		}

		if !matchFound {
			output.Failed = true
			output.FailReason = fmt.Sprintf("Output missing required pattern: %s", rule.Excludes)
			output.Remediation = rule.Remediation
			return nil
		}
	}

	// Check exit code (fail if matches)
	if rule.ExitCode != nil && output.ExitCode == *rule.ExitCode {
		output.Failed = true
		output.FailReason = fmt.Sprintf("Exit code %d indicates failure", output.ExitCode)
		output.Remediation = rule.Remediation
		return nil
	}

	// If no criteria specified, it's informational only
	return nil
}

// DetermineOverallStatus determines the overall status of a check based on all outputs.
func DetermineOverallStatus(outputs []gitmdm.CommandOutput) (status string, reason string, remediation []string) {
	hasFailure := false
	hasSuccess := false
	allSkipped := true

	var failReasons []string
	var allRemediation []string
	remediationSeen := make(map[string]bool)

	for _, output := range outputs {
		if output.Failed {
			hasFailure = true
			allSkipped = false
			if output.FailReason != "" {
				failReasons = append(failReasons, output.FailReason)
			}
			// Collect unique remediation steps
			for _, step := range output.Remediation {
				if !remediationSeen[step] {
					allRemediation = append(allRemediation, step)
					remediationSeen[step] = true
				}
			}
		} else if !output.Skipped && !output.FileMissing {
			hasSuccess = true
			allSkipped = false
		}
	}

	// Determine overall status
	switch {
	case hasFailure:
		status = "fail"
		switch {
		case len(failReasons) == 1:
			reason = failReasons[0]
		case len(failReasons) > 1:
			reason = strings.Join(failReasons, "; ")
		default:
			reason = "Check failed"
		}
		remediation = allRemediation
	case hasSuccess:
		status = "pass"
		reason = "Check passed"
	case allSkipped:
		status = "n/a"
		reason = "Check not applicable"
	default:
		status = "n/a"
		reason = "Unable to determine status"
	}

	return status, reason, remediation
}
