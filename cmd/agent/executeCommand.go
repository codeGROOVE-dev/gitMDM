package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os/exec"
	"time"

	"gitmdm/internal/types"
)

// executeCommandWithPipes executes a command and captures stdout/stderr separately
func (*Agent) executeCommandWithPipes(ctx context.Context, checkName, command string) types.Check {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	if *debug {
		log.Printf("[DEBUG] Executing command: %s", command)
	}

	// Use bash -r for restricted mode security
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
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
			stderr += fmt.Sprintf("\nCommand error: %v", err)
		}
	}

	// Log stdout/stderr for debugging with check name
	prefix := ""
	if checkName != "" {
		prefix = fmt.Sprintf("[%s] ", checkName)
	}
	
	if stdout != "" {
		log.Printf("[INFO] %sCommand stdout (%d bytes): %s", prefix, len(stdout), truncateForLog(stdout, 200))
	}
	if stderr != "" {
		log.Printf("[INFO] %sCommand stderr (%d bytes): %s", prefix, len(stderr), truncateForLog(stderr, 200))
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

// limitOutput truncates output if it exceeds maxSize
func limitOutput(data []byte, maxSize int) string {
	if len(data) > maxSize {
		truncated := data[:maxSize]
		return string(truncated) + "\n[Output truncated to 10KB]..."
	}
	return string(data)
}

// truncateForLog truncates a string for logging purposes
func truncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// limitedRead reads from a reader up to maxBytes
func limitedRead(r io.Reader, maxBytes int) string {
	limited := &io.LimitedReader{R: r, N: int64(maxBytes)}
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Sprintf("Error reading output: %v", err)
	}

	// Check if output was truncated
	if limited.N == 0 {
		// Try to read one more byte to see if there's more data
		extraByte := make([]byte, 1)
		if n, _ := r.Read(extraByte); n > 0 {
			return string(data) + "\n[Output truncated to 10KB]..."
		}
	}

	return string(data)
}