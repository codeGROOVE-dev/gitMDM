package main

import (
	"context"
	"fmt"
	"gitmdm/internal/analyzer"
	"gitmdm/internal/config"
	"gitmdm/internal/gitmdm"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
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
func checkCommandAvailable(checkName, command string) *gitmdm.CommandOutput {
	if containsShellOperators(command) {
		return nil // Commands with shell operators need shell interpretation
	}

	commandParts := strings.Fields(command)
	if len(commandParts) == 0 {
		return nil
	}

	primaryCmd := commandParts[0]
	if isShellBuiltin(primaryCmd) || strings.Contains(primaryCmd, "/") {
		return nil // Shell builtins and absolute paths don't need validation
	}

	// Temporarily set PATH for LookPath
	oldPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", securePath()); err != nil {
		log.Printf("[WARN] Failed to set PATH for command check: %v", err)
	}
	_, lookupErr := exec.LookPath(primaryCmd)
	if err := os.Setenv("PATH", oldPath); err != nil {
		log.Printf("[WARN] Failed to restore PATH: %v", err)
	}

	if lookupErr != nil {
		if *debugMode {
			log.Printf("[DEBUG] Command '%s' not found in PATH for check '%s', skipping", primaryCmd, checkName)
		}
		return &gitmdm.CommandOutput{
			Command:     command,
			Skipped:     true,
			FileMissing: true, // Treat missing command like missing file
			Stderr:      fmt.Sprintf("Skipped: %s not found", primaryCmd),
		}
	}
	return nil
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
