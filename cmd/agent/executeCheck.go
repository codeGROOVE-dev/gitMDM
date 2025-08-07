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

	if *debug {
		log.Printf("[DEBUG] Reading file for check %s: %s", checkName, rule.File)
	}

	content, err := os.ReadFile(rule.File)

	output := gitmdm.CommandOutput{
		File: rule.File,
	}

	if err != nil {
		if os.IsNotExist(err) {
			output.FileMissing = true
			if *debug {
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

	if *debug {
		log.Printf("[DEBUG] File read completed in %v (missing: %v, failed: %v): %s",
			time.Since(start), output.FileMissing, output.Failed, rule.File)
	}

	return output
}

// executeCommand executes a command and returns its output.
func (a *Agent) executeCommand(ctx context.Context, checkName string, rule config.CommandRule) gitmdm.CommandOutput {
	start := time.Now()
	command := rule.Output

	// Extract the primary command (first word) to check if it exists
	commandParts := strings.Fields(command)
	if len(commandParts) > 0 {
		primaryCmd := commandParts[0]

		// Check if this is a shell builtin or special command
		shellBuiltins := map[string]bool{
			"echo": true, "test": true, "[": true, "[[": true, "if": true,
			"then": true, "else": true, "fi": true, "for": true, "while": true,
			"do": true, "done": true, "case": true, "esac": true, "function": true,
			"return": true, "break": true, "continue": true, "exit": true,
			"source": true, ".": true, "eval": true, "exec": true, "export": true,
			"unset": true, "shift": true, "cd": true, "pwd": true, "read": true,
			"readonly": true, "declare": true, "typeset": true, "local": true,
			"true": true, "false": true, "type": true, "command": true,
			// Include sudo and doas since they're commonly used
			"sudo": true, "doas": true,
		}

		// If it's not a shell builtin and not a path, check if the command exists
		if !shellBuiltins[primaryCmd] && !strings.Contains(primaryCmd, "/") {
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
				if *debug {
					log.Printf("[DEBUG] Command '%s' not found in PATH for check '%s', skipping", primaryCmd, checkName)
				}

				output := gitmdm.CommandOutput{
					Command:     command,
					Skipped:     true,
					FileMissing: true, // Treat missing command like missing file
					Stderr:      fmt.Sprintf("Skipped: %s not found", primaryCmd),
				}

				// Don't analyze skipped commands
				return output
			}
		}
	}

	// Use longer timeout for software update checks (they contact remote servers)
	timeout := commandTimeout
	if checkName == "available_updates" || checkName == "automatic_updates" {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if *debug {
		log.Printf("[DEBUG] Executing command: %s", command)
	}

	// Execute the command
	output := a.executeCommandWithPipes(ctx, checkName, command)

	// Analyze against the rule
	if err := analyzer.AnalyzeCheck(&output, rule); err != nil {
		log.Printf("[ERROR] Failed to analyze command check: %v", err)
	}

	if *debug {
		log.Printf("[DEBUG] Command completed in %v (skipped: %v, failed: %v): %s",
			time.Since(start), output.Skipped, output.Failed, command)
	}

	return output
}
