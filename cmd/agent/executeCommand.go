package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"gitmdm/internal/gitmdm"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// containsShellOperators checks if a command contains shell operators that indicate
// it needs shell interpretation (pipes, redirects, command chaining, subshells, etc).
func containsShellOperators(command string) bool {
	shellOperators := []string{"|", "&", ";", ">", "<", "(", ")", "{", "}", "$", "`", "||", "&&"}
	for _, op := range shellOperators {
		if strings.Contains(command, op) {
			return true
		}
	}
	return false
}

// securePath returns a secure PATH based on the OS.
func securePath() string {
	switch runtime.GOOS {
	case "windows":
		return "C:\\Windows\\System32;C:\\Windows;C:\\Windows\\System32\\wbem"
	case "darwin":
		// macOS standard paths + ApplicationFirewall for socketfilterfw
		return "/usr/libexec/ApplicationFirewall:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	case "linux":
		return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		// BSD systems often have important tools in /usr/local
		return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	case "solaris", "illumos":
		// Solaris/Illumos have additional paths
		return "/usr/sbin:/usr/bin:/sbin:/bin:/usr/gnu/bin:/opt/local/bin"
	default:
		// Safe default for unknown Unix-like systems
		return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
}

// isShellBuiltin checks if a command is a shell builtin.
func isShellBuiltin(cmd string) bool {
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
	return shellBuiltins[cmd]
}

// logCommandOutput logs command output for debugging.
func logCommandOutput(checkName, command, stdout, stderr string, exitCode int, duration time.Duration) {
	if quiet {
		return
	}

	prefix := ""
	if checkName != "" {
		prefix = fmt.Sprintf("[%s] ", checkName)
	}

	// Log non-empty stdout
	if stdout != "" && strings.TrimSpace(stdout) != "" {
		trimmed := strings.TrimSpace(stdout)
		if len(trimmed) > maxLogLength {
			trimmed = trimmed[:maxLogLength] + "..."
		}
		log.Printf("[INFO] %sstdout (%d bytes): %s", prefix, len(stdout), trimmed)
	}

	// Log non-empty stderr
	if stderr != "" && strings.TrimSpace(stderr) != "" {
		trimmed := strings.TrimSpace(stderr)
		if len(trimmed) > maxLogLength {
			trimmed = trimmed[:maxLogLength] + "..."
		}
		log.Printf("[INFO] %sstderr (%d bytes): %s", prefix, len(stderr), trimmed)
	}

	if *debugMode {
		log.Printf("[DEBUG] Command completed in %v (exit: %d, stdout: %d bytes, stderr: %d bytes): %s",
			duration, exitCode, len(stdout), len(stderr), command)
	}
}

// validateCommand checks if a command exists in PATH.
func validateCommand(checkName, command string) *gitmdm.CommandOutput {
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
			Command:  command,
			Stdout:   "",
			Stderr:   fmt.Sprintf("Skipped: %s not found", primaryCmd),
			ExitCode: -2, // Special exit code for skipped
		}
	}
	return nil
}

// executeCommandWithPipes executes a command and captures stdout/stderr separately.
// SECURITY: Commands come from checks.yaml which must be controlled by the system admin.
// We set a minimal secure PATH to prevent PATH-based attacks.
// The agent runs with user privileges only.
func (*Agent) executeCommandWithPipes(ctx context.Context, checkName, command string) gitmdm.CommandOutput {
	start := time.Now()

	// Validate command exists
	if result := validateCommand(checkName, command); result != nil {
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

	// Choose shell based on OS
	// Security: Set minimal PATH for security
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", command)
	default:
		// Unix-like systems use sh for better compatibility
		// Note: bash -r prevents absolute paths, so we use sh with controlled PATH
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}

	// Set a secure, minimal PATH for the subprocess
	securePath := securePath()
	if *debugMode {
		log.Printf("[DEBUG] Using secure PATH for %s: %s", runtime.GOOS, securePath)
	}
	cmd.Env = append(os.Environ(), "PATH="+securePath)

	// Capture stdout
	var stdoutBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf

	// Capture stderr
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	// Run the command
	err := cmd.Run()
	duration := time.Since(start)

	// Limit output sizes
	stdoutBytes := stdoutBuf.Bytes()
	stdout := string(stdoutBytes)
	if len(stdoutBytes) > maxOutputSize {
		stdout = string(stdoutBytes[:maxOutputSize]) + "\n[Output truncated to 90KB]..."
	}

	stderrBytes := stderrBuf.Bytes()
	stderr := string(stderrBytes)
	if len(stderrBytes) > maxOutputSize {
		stderr = string(stderrBytes[:maxOutputSize]) + "\n[Output truncated to 90KB]..."
	}

	// Determine exit code
	exitCode := 0
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			if !quiet {
				log.Printf("[WARN] Command timed out after %v: %s", duration, command)
			}
			stderr = "Command timed out after " + duration.String()
			exitCode = -1
		} else {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
				stderr += fmt.Sprintf("\nCommand error: %v", err)
			}
		}
	}

	// Log command output
	logCommandOutput(checkName, command, stdout, stderr, exitCode, duration)

	return gitmdm.CommandOutput{
		Command:  command,
		Stdout:   stdout,
		Stderr:   stderr,
		ExitCode: exitCode,
	}
}
