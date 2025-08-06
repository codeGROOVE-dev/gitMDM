package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"gitmdm/internal/types"
)

// executeCommandWithPipes executes a command and captures stdout/stderr separately.
// SECURITY: Commands come from checks.yaml which must be controlled by the system admin.
// Bash restricted mode (-r) prevents: cd, PATH changes, output redirection, running programs
// with / in name. Complex shell operations (pipes, grep, awk) are still allowed by design
// as they're needed for compliance checks. The agent runs with user privileges only.
func (*Agent) executeCommandWithPipes(ctx context.Context, checkName, command string) types.Check {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	if *debug {
		log.Printf("[DEBUG] Executing command: %s", command)
	}

	// Use bash -r for restricted mode security
	// Security: This is as safe as we can make arbitrary command execution
	cmd := exec.CommandContext(ctx, "bash", "-r", "-c", command)

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
	stdout := limitOutput(stdoutBuf.Bytes(), maxOutputSize)
	stderr := limitOutput(stderrBuf.Bytes(), maxOutputSize)

	// Determine exit code
	exitCode := 0
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("[WARN] Command timed out after %v: %s", duration, command)
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

	// Log stdout/stderr for debugging with check name
	prefix := ""
	if checkName != "" {
		prefix = fmt.Sprintf("[%s] ", checkName)
	}

	// Only log non-empty outputs
	if stdout != "" && strings.TrimSpace(stdout) != "" {
		trimmed := strings.TrimSpace(stdout)
		if len(trimmed) > maxLogLength {
			trimmed = trimmed[:maxLogLength] + "..."
		}
		log.Printf("[INFO] %sstdout (%d bytes): %s", prefix, len(stdout), trimmed)
	}
	if stderr != "" && strings.TrimSpace(stderr) != "" {
		trimmed := strings.TrimSpace(stderr)
		if len(trimmed) > maxLogLength {
			trimmed = trimmed[:maxLogLength] + "..."
		}
		log.Printf("[INFO] %sstderr (%d bytes): %s", prefix, len(stderr), trimmed)
	}

	if *debug {
		log.Printf("[DEBUG] Command completed in %v (exit: %d, stdout: %d bytes, stderr: %d bytes): %s",
			duration, exitCode, len(stdout), len(stderr), command)
	}

	return types.Check{
		Command:  command,
		Stdout:   stdout,
		Stderr:   stderr,
		ExitCode: exitCode,
	}
}

// limitOutput truncates output if it exceeds maxSize.
func limitOutput(data []byte, maxSize int) string {
	if len(data) > maxSize {
		truncated := data[:maxSize]
		return string(truncated) + "\n[Output truncated to 10KB]..."
	}
	return string(data)
}
