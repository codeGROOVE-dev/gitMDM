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

// executeCommandWithPipes executes a command and captures stdout/stderr separately.
// SECURITY: Commands come from checks.yaml which must be controlled by the system admin.
// Commands MUST use absolute paths to prevent PATH-based attacks.
// We use bash -r (restricted mode) with a minimal secure PATH.
// The agent runs with user privileges only.
func (*Agent) executeCommandWithPipes(ctx context.Context, checkName, command string) gitmdm.CommandOutput {
	start := time.Now()

	// Use longer timeout for software update checks (they contact remote servers)
	timeout := commandTimeout
	if checkName == "software_updates" {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if *debug {
		log.Printf("[DEBUG] Executing command: %s", command)
	}

	// Choose shell based on OS
	// Security: Use restricted mode when available, set minimal PATH
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// Windows uses cmd.exe
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", command)
	case "linux", "darwin":
		// Linux and macOS typically have bash
		cmd = exec.CommandContext(ctx, "bash", "-r", "-c", command)
	default:
		// BSD and other Unix systems - use sh which is POSIX standard
		// Note: sh doesn't have -r flag, but we control PATH for security
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}

	// Set a secure, minimal PATH for the subprocess based on OS
	// This allows commands to be found while preventing PATH attacks
	var securePath string
	switch runtime.GOOS {
	case "windows":
		securePath = "C:\\Windows\\System32;C:\\Windows;C:\\Windows\\System32\\wbem"
	case "darwin":
		// macOS standard paths + ApplicationFirewall for socketfilterfw
		securePath = "/usr/libexec/ApplicationFirewall:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	case "linux":
		// Linux standard paths (no /usr/local for security)
		securePath = "/usr/sbin:/usr/bin:/sbin:/bin"
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		// BSD standard paths
		securePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	case "solaris", "illumos":
		// Solaris/illumos paths
		securePath = "/usr/sbin:/usr/bin:/sbin:/bin"
	default:
		// Fallback for unknown Unix-like systems
		securePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}

	if *debug {
		log.Printf("[DEBUG] Using secure PATH for %s: %s", runtime.GOOS, securePath)
	}

	// Set the environment with our secure PATH
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

	// Log stdout/stderr for debugging with check name
	prefix := ""
	if checkName != "" {
		prefix = fmt.Sprintf("[%s] ", checkName)
	}

	// Only log non-empty outputs (unless in quiet mode)
	if !quiet {
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
	}

	if *debug {
		log.Printf("[DEBUG] Command completed in %v (exit: %d, stdout: %d bytes, stderr: %d bytes): %s",
			duration, exitCode, len(stdout), len(stderr), command)
	}

	return gitmdm.CommandOutput{
		Command:  command,
		Stdout:   stdout,
		Stderr:   stderr,
		ExitCode: exitCode,
	}
}
