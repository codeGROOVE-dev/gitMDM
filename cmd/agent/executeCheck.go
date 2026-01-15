package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/codeGROOVE-dev/gitMDM/internal/analyzer"
	"github.com/codeGROOVE-dev/gitMDM/internal/config"
	"github.com/codeGROOVE-dev/gitMDM/internal/gitmdm"
)

// executeCheck executes a single check rule (command or file) and returns the output.
func (a *Agent) executeCheck(ctx context.Context, checkName string, rule config.CommandRule) gitmdm.CommandOutput {
	// Handle file checks
	if rule.File != "" {
		return a.readFile(checkName, rule)
	}

	// Handle command checks
	if rule.Output != "" {
		return a.executeCommand(ctx, checkName, rule)
	}

	// Empty rule
	return gitmdm.CommandOutput{
		Skipped:    true,
		FailReason: "No command or file specified",
	}
}

// readFile reads a file and returns its contents as a CommandOutput.
func (*Agent) readFile(checkName string, rule config.CommandRule) gitmdm.CommandOutput {
	start := time.Now()

	if *debugMode {
		log.Printf("[DEBUG] Reading file for check %s: %s", checkName, rule.File)
	}

	content, err := os.ReadFile(rule.File)

	output := gitmdm.CommandOutput{
		File: rule.File,
	}

	if err != nil {
		if os.IsNotExist(err) {
			output.FileMissing = true
			if *debugMode {
				log.Printf("[DEBUG] File not found for check %s: %s", checkName, rule.File)
			}
		} else {
			output.Stderr = fmt.Sprintf("Error reading file: %v", err)
			output.ExitCode = 1
		}
	} else {
		output.Stdout = string(content)
		output.ExitCode = 0

		// Limit file size
		if len(output.Stdout) > maxOutputSize {
			output.Stdout = output.Stdout[:maxOutputSize] + "\n[File truncated to 90KB]..."
		}
	}

	// Analyze against the rule
	if err := analyzer.AnalyzeCheck(&output, rule); err != nil {
		log.Printf("[ERROR] Failed to analyze file check: %v", err)
	}

	if *debugMode {
		log.Printf("[DEBUG] File read completed in %v (missing: %v, failed: %v): %s",
			time.Since(start), output.FileMissing, output.Failed, rule.File)
	}

	return output
}

// checkCommandAvailable verifies that a command is available to execute.
// This is a wrapper around validateCommand that sets the appropriate fields for executeCheck.
func checkCommandAvailable(checkName, command string) *gitmdm.CommandOutput {
	output := validateCommand(checkName, command)
	if output != nil {
		// Convert exitCode -2 to Skipped/FileMissing for executeCheck
		output.Skipped = true
		output.FileMissing = true
		output.ExitCode = 0
	}
	return output
}

// executeCommand executes a command and returns its output.
func (a *Agent) executeCommand(ctx context.Context, checkName string, rule config.CommandRule) gitmdm.CommandOutput {
	start := time.Now()
	command := rule.Output

	// Check if command is available
	if result := checkCommandAvailable(checkName, command); result != nil {
		return *result
	}

	// Use longer timeout for software update checks (they contact remote servers)
	timeout := commandTimeout
	if checkName == "available_updates" || checkName == "automatic_updates" {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if *debugMode {
		log.Printf("[DEBUG] Executing command: %s", command)
	}

	// Execute the command
	output := a.executeCommandWithPipes(ctx, checkName, command)

	// Analyze against the rule
	if err := analyzer.AnalyzeCheck(&output, rule); err != nil {
		log.Printf("[ERROR] Failed to analyze command check: %v", err)
	}

	if *debugMode {
		log.Printf("[DEBUG] Command completed in %v (skipped: %v, failed: %v): %s",
			time.Since(start), output.Skipped, output.Failed, command)
	}

	return output
}
