// Package analyzer provides compliance check analysis and grading.
package analyzer

import (
	"strings"
)

// Result represents the analysis result of a compliance check.
type Result struct {
	Status      string   // "pass", "fail", "n/a"
	Description string   // Human-readable description
	Remediation []string // Command-specific remediation steps
}

// AnalyzeCheck analyzes the output of a compliance check and returns pass/fail status.
// Takes into account the OS and specific command being run for more accurate analysis.
func AnalyzeCheck(checkName string, osName string, command string, stdout string, stderr string, exitCode int) Result {
	// Handle timeout case explicitly (timeout results in exitCode -1)
	if exitCode == -1 && strings.Contains(stderr, "Command timed out") {
		return Result{Status: "n/a", Description: "Check timed out - try again later"}
	}

	// Combine output for analysis
	output := strings.ToLower(stdout + stderr)

	// Extract the base command (first word) for command-specific analysis
	baseCommand := ""
	if command != "" {
		parts := strings.Fields(command)
		if len(parts) > 0 {
			baseCommand = parts[0]
		}
	}

	switch checkName {
	case "disk_encryption":
		return analyzeDiskEncryption(output, osName, baseCommand)
	case "firewall":
		return analyzeFirewall(output, exitCode, osName, baseCommand)
	case "app_firewall":
		return analyzeAppFirewall(output, exitCode, osName, baseCommand)
	case "screen_lock":
		return analyzeScreenLock(output, osName, baseCommand, command)
	case "auto_login":
		return analyzeAutoLogin(output, osName, baseCommand)
	case "password_policy":
		return analyzePasswordPolicy(output, osName, baseCommand, command)
	case "updates", "software_updates":
		return analyzeUpdates(output, osName, baseCommand, exitCode)
	case "antivirus":
		return analyzeAntivirus(output, osName)
	case "hostname", "uname", "users", "network", "system_info":
		// Informational checks - no pass/fail
		return Result{Status: "n/a", Description: "Informational"}
	default:
		// Unknown check - can't grade
		return Result{Status: "n/a", Description: "No compliance criteria defined"}
	}
}
