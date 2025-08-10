// Package main implements the gitMDM agent that collects compliance data.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"gitmdm/internal/analyzer"
	"gitmdm/internal/config"
	"gitmdm/internal/gitmdm"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/codeGROOVE-dev/retry"
	"gopkg.in/yaml.v3"
)

const (
	// Version of the agent.
	version = "1.0.0"

	// Command execution timeout.
	commandTimeout = 10 * time.Second

	// OS constants.
	osWindows = "windows"
	osDarwin  = "darwin"
	osLinux   = "linux"

	// Windows command constants.
	wmicCmd    = "wmic"
	wmicGetArg = "get"
	// Maximum output size to prevent memory exhaustion.
	maxOutputSize = 92160 // 90KB limit (matching server)
	// Maximum log output length for readability.
	maxLogLength = 200
	// Minimum parts required for IOPlatformUUID parsing.
	minUUIDParts = 4
	// Retry configuration - using exponential backoff with jitter up to 2 minutes total.
	maxRetries     = 7 // More attempts to handle transient failures
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second // Per-retry max delay to fit within 2 minute total
	// HTTP client timeout.
	httpTimeout = 30 * time.Second
	// Queue size for failed reports.
	failedReportsQueueSize = 100
	// Response body read limit for error messages.
	maxResponseBodyBytes = 256
	// Display constants for interactive mode.
	maxDisplayLines = 5
	maxVerboseLines = 20
	// Status constants.
	statusFail = "fail"
	statusPass = "pass"
)

//go:embed checks.yaml
var checksConfig []byte

var (
	server     = flag.String("server", "", "Server URL (e.g., http://localhost:8080)")
	join       = flag.String("join", "", "Join key for registration (required when using --server)")
	runCheck   = flag.String("run", "", "Run a single check and exit (use 'all' to run all checks)")
	listChecks = flag.Bool("list", false, "List available compliance checks")
	interval   = flag.Duration("interval", 20*time.Minute, "Polling interval")
	debugMode  = flag.Bool("debug", false, "Enable debug logging")
	verbose    = flag.Bool("verbose", false, "Show all check outputs, not just failures (with --run all)")
	install    = flag.Bool("install", false, "Install agent to run automatically at startup")
	uninstall  = flag.Bool("uninstall", false, "Uninstall agent and remove autostart")
	quiet      = false // Set to true to suppress INFO logs (used for interactive mode)
)

// Agent represents the gitMDM agent that collects compliance data.
type Agent struct {
	config        *config.Config
	httpClient    *http.Client
	failedReports chan gitmdm.DeviceReport
	serverURL     string
	joinKey       string
	hardwareID    string
	hostname      string
	user          string
}

// normalizeServerURL ensures the server URL has a protocol and removes trailing slash.
func normalizeServerURL(url string) string {
	// Add https:// if no protocol is specified
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		log.Printf("[INFO] No protocol specified for %s, using https://", url)
		url = "https://" + url
	}
	// Remove trailing slash
	return strings.TrimSuffix(url, "/")
}

// handleInstall handles the agent installation process.
func (a *Agent) handleInstall() error {
	if *server == "" || *join == "" {
		return errors.New("--server and --join flags are required for installation")
	}

	// Set up agent configuration for verification
	a.serverURL = normalizeServerURL(*server)
	a.joinKey = *join

	// Verify server connection and join key by sending a test report
	log.Println("Verifying server connection and join key...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run checks and attempt to report to server
	report := a.buildDeviceReport(ctx)

	// Retry the verification with exponential backoff
	if err := a.verifyServerConnection(ctx, report); err != nil {
		cancel()
		return fmt.Errorf("failed to verify server connection after %d attempts: %v\n"+
			"Please check your --server and --join parameters", maxRetries+1, err)
	}

	log.Println("✓ Server connection verified successfully")
	log.Printf("✓ Device registered as: %s (%s)", a.hostname, a.hardwareID)

	// Now proceed with installation
	if err := installAgent(*server, *join); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}
	log.Println("✓ Agent installed successfully and will run automatically at startup")
	return nil
}

// verifyServerConnection verifies the server connection with retries.
func (a *Agent) verifyServerConnection(ctx context.Context, report gitmdm.DeviceReport) error {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(float64(initialBackoff) * math.Pow(2, float64(attempt-1)))
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			log.Printf("[INFO] Retrying verification (attempt %d/%d) after %v...", attempt, maxRetries, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		if err := a.sendReport(ctx, report); err != nil {
			lastErr = err
			log.Printf("[WARN] Verification attempt %d failed: %v", attempt+1, err)
			continue
		}
		// Success!
		return nil
	}
	return lastErr
}

// buildDeviceReport builds a complete device report.
func (a *Agent) buildDeviceReport(ctx context.Context) gitmdm.DeviceReport {
	return gitmdm.DeviceReport{
		HardwareID:    a.hardwareID,
		Hostname:      a.hostname,
		User:          a.user,
		Timestamp:     time.Now(),
		Checks:        a.runAllChecks(ctx),
		OS:            a.osInfo(ctx),
		Architecture:  runtime.GOARCH, // Directly get architecture
		Version:       a.osVersion(ctx),
		SystemUptime:  a.systemUptime(ctx),
		CPULoad:       a.cpuLoad(ctx),
		LoggedInUsers: a.loggedInUsers(ctx),
	}
}

// configureServerConnection configures the server connection from flags or config file.
func (a *Agent) configureServerConnection() error {
	// Try to load config file if server/join not provided via flags
	if *server == "" || *join == "" {
		cfg, err := loadConfig()
		if err != nil {
			// Config file doesn't exist or is invalid
			if *server == "" {
				return errors.New("server URL is required (use --server flag or install agent with --install)")
			}
			if *join == "" {
				return errors.New("join key is required (use --join flag or install agent with --install)")
			}
		} else {
			// Use config file values if flags not provided
			if *server == "" {
				*server = cfg.ServerURL
			}
			if *join == "" {
				*join = cfg.JoinKey
			}
		}
	}

	a.serverURL = normalizeServerURL(*server)
	a.joinKey = *join
	return nil
}

// initializeAgent creates and initializes an Agent instance.
func initializeAgent() (*Agent, error) {
	var cfg config.Config
	if err := yaml.Unmarshal(checksConfig, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse checks config: %w", err)
	}

	// Get hostname directly
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Get current user directly
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	if user == "" {
		user = "unknown"
	}

	return &Agent{
		config:     &cfg,
		hardwareID: hardwareID(),
		hostname:   hostname,
		user:       user,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
		failedReports: make(chan gitmdm.DeviceReport, failedReportsQueueSize),
	}, nil
}

// setupLogging configures logging to both console and file.
func setupLogging() (*os.File, error) {
	// Create log directory if it doesn't exist
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	logDir := filepath.Join(homeDir, ".gitmdm")
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file for appending (only accessible by user)
	logPath := filepath.Join(logDir, "agent.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// Set up multi-writer to log to both console and file
	multiWriter := io.MultiWriter(os.Stderr, logFile)
	log.SetOutput(multiWriter)

	// Add timestamp to logs
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	return logFile, nil
}

// checkAndCreatePIDFile checks if another instance is running and creates a PID file.
// Returns true if we should continue running, false if another instance is active.
func checkAndCreatePIDFile() (exists bool, cleanup func()) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Printf("[WARN] Failed to get home directory for PID file: %v", err)
		return true, func() {} // Continue without PID file
	}

	pidPath := filepath.Join(homeDir, ".gitmdm", "agent.pid")
	// Check if PID file exists and if that process is still running
	if pidData, err := os.ReadFile(pidPath); err == nil {
		oldPID, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
		if err == nil {
			// Check if process exists by sending signal 0
			if process, err := os.FindProcess(oldPID); err == nil {
				if err := process.Signal(syscall.Signal(0)); err == nil {
					log.Printf("[INFO] Agent already running with PID %d, exiting", oldPID)
					return false, func() {}
				}
			}
			log.Printf("[INFO] Removing stale PID file for non-existent process %d", oldPID)
		}
	}

	// Write our PID
	pid := os.Getpid()
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(pid)), 0o600); err != nil {
		log.Printf("[WARN] Failed to write PID file: %v", err)
		return true, func() {} // Continue without PID file
	}

	log.Printf("[INFO] Created PID file with PID %d", pid)

	// Return cleanup function
	cleanup = func() {
		if err := os.Remove(pidPath); err != nil && !os.IsNotExist(err) {
			log.Printf("[WARN] Failed to remove PID file: %v", err)
		} else {
			log.Print("[INFO] Removed PID file")
		}
	}

	return true, cleanup
}

func main() {
	// Set up panic recovery first
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] Agent crashed: %v\nStack trace:\n%s", r, debug.Stack())
			os.Exit(1)
		}
	}()

	flag.Parse()

	// Set up file logging (non-fatal if it fails)
	var logFile *os.File
	if lf, err := setupLogging(); err != nil {
		log.Printf("[WARN] Failed to set up file logging: %v", err)
	} else {
		logFile = lf
		defer func() {
			if err := logFile.Close(); err != nil {
				log.Printf("[WARN] Failed to close log file: %v", err)
			}
		}()
		log.Printf("[INFO] Agent starting - version %s, PID %d", version, os.Getpid())
	}

	agent, err := initializeAgent()
	if err != nil {
		if logFile != nil {
			_ = logFile.Close() //nolint:errcheck // Best effort before exiting
		}
		log.Fatal(err) //nolint:gocritic // exitAfterDefer - panic recovery needed
	}

	// Handle --list flag
	if *listChecks {
		agent.listAvailableChecks()
		return
	}

	// Handle --install flag
	if *install {
		if err := agent.handleInstall(); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Handle --uninstall flag
	if *uninstall {
		if err := uninstallAgent(); err != nil {
			log.Fatalf("Uninstallation failed: %v", err)
		}
		log.Println("Agent uninstalled successfully")
		return
	}

	// Handle --run flag
	if *runCheck != "" {
		if *runCheck == "all" {
			agent.runAllChecksInteractive()
		} else {
			// Security: Validate check name to prevent injection
			if !gitmdm.IsValidCheckName(*runCheck) {
				log.Fatal("Invalid check name - only alphanumeric and underscore allowed")
			}
			output := agent.runSingleCheck(*runCheck)
			log.Print(output)
			if !strings.HasSuffix(output, "\n") {
				log.Print("\n")
			}
		}
		return
	}

	// Configure server connection
	if err := agent.configureServerConnection(); err != nil {
		log.Printf("[ERROR] Failed to configure server connection: %v", err)
		log.Print("[INFO] Agent will continue running in offline mode, collecting data locally")
		// Continue in offline mode - we can still collect data even if server is not configured
		agent.serverURL = ""
	}

	// Check PID file to avoid duplicate processes
	shouldRun, cleanupPID := checkAndCreatePIDFile()
	if !shouldRun {
		return // Another instance is already running
	}
	defer cleanupPID()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	log.Printf("[INFO] Agent started. Hardware ID: %s, Hostname: %s, User: %s", agent.hardwareID, agent.hostname, agent.user)
	log.Printf("[INFO] Reporting to server: %s every %v", agent.serverURL, *interval)
	log.Printf("[INFO] Retry configuration: max_retries=%d, initial_backoff=%v, max_backoff=%v", maxRetries, initialBackoff, maxBackoff)

	// Start failed reports processor with panic recovery
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PANIC] Failed reports processor crashed: %v\nStack trace:\n%s", r, debug.Stack())
			}
		}()
		agent.processFailedReports(ctx)
	}()

	// Initial report
	log.Println("[INFO] Sending initial report to server")
	agent.reportToServer(ctx)

	log.Println("[INFO] Agent main loop started, waiting for next interval or shutdown signal")
	for {
		select {
		case <-ticker.C:
			log.Printf("[INFO] Interval elapsed (%v), sending report", *interval)
			agent.reportToServer(ctx)
		case sig := <-sigChan:
			log.Printf("[INFO] Received signal %v, shutting down agent gracefully", sig)
			return
		case <-ctx.Done():
			log.Println("[INFO] Context cancelled, shutting down agent")
			return
		}
	}
}

func (a *Agent) reportToServer(ctx context.Context) {
	start := time.Now()
	report := a.buildDeviceReport(ctx)

	if *debugMode {
		log.Printf("[DEBUG] Generated report with %d checks in %v", len(report.Checks), time.Since(start))
	}

	// If no server configured (offline mode), just log the collection
	if a.serverURL == "" {
		log.Print("[INFO] Running in offline mode - data collected but not sent to server")
		if *debugMode {
			log.Printf("[DEBUG] Collected %d checks in offline mode", len(report.Checks))
		}
		return
	}

	retryCount := 0
	err := retry.Do(func() error {
		retryCount++
		if retryCount > 1 {
			log.Printf("[INFO] Retry attempt %d/%d for sending report", retryCount, maxRetries)
		}
		return a.sendReport(ctx, report)
	}, retry.Attempts(maxRetries), retry.DelayType(retry.FullJitterBackoffDelay), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff))
	if err != nil {
		log.Printf("[ERROR] Failed to send report after %d attempts: %v", retryCount, err)
		// Queue for later retry if queue not full
		select {
		case a.failedReports <- report:
			log.Print("[INFO] Report queued for retry processing")
		default:
			log.Print("[WARN] Failed reports queue is full, dropping report")
		}
		return
	}

	// Log success, noting if retries were needed
	if retryCount > 1 {
		log.Printf("[INFO] Successfully reported to server after %d attempts (took %v)", retryCount, time.Since(start))
	} else if *debugMode {
		log.Printf("[DEBUG] Successfully reported to server in %v", time.Since(start))
	}
}

func (a *Agent) sendReport(ctx context.Context, report gitmdm.DeviceReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.serverURL+"/api/v1/report", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Join-Key", a.joinKey)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed to send report to %s: %v", a.serverURL, err)
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("[WARN] Error closing response body: %v", err)
		}
	}()

	// Log the HTTP response code
	log.Printf("[INFO] Report sent to %s - Response: %d %s", a.serverURL, resp.StatusCode, resp.Status)

	if resp.StatusCode != http.StatusOK {
		// Read response body for debugging (limit to 256 bytes)
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
		if err != nil {
			log.Printf("[ERROR] Server returned %d but failed to read response body: %v", resp.StatusCode, err)
			return fmt.Errorf("server returned status %d (failed to read body: %w)", resp.StatusCode, err)
		}
		errorMsg := string(bodyBytes)
		log.Printf("[ERROR] Server returned %d: %s", resp.StatusCode, errorMsg)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, errorMsg)
	}

	return nil
}

func (a *Agent) processFailedReports(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Process all queued reports
			for {
				select {
				case report := <-a.failedReports:
					a.retryFailedReport(ctx, report)
				default:
					// No more reports to process
					goto nextTick
				}
			}
		nextTick:
		}
	}
}

func (a *Agent) retryFailedReport(ctx context.Context, report gitmdm.DeviceReport) {
	log.Printf("[INFO] Retrying failed report for device %s", report.HardwareID)
	err := retry.Do(func() error {
		return a.sendReport(ctx, report)
	},
		retry.Attempts(maxRetries),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.Delay(initialBackoff),
		retry.MaxDelay(maxBackoff))

	if err != nil {
		log.Printf("[ERROR] Failed to retry report: %v", err)
		// Re-queue if there's space, otherwise drop
		select {
		case a.failedReports <- report:
		default:
			log.Print("[WARN] Dropping failed report - queue full")
		}
	} else {
		log.Print("[INFO] Successfully sent queued report")
	}
}

func (a *Agent) runAllChecks(ctx context.Context) map[string]gitmdm.Check {
	start := time.Now()
	checks := make(map[string]gitmdm.Check)
	osName := runtime.GOOS
	successCount := 0
	failureCount := 0

	if *debugMode {
		log.Printf("[DEBUG] Running %d checks for OS: %s", len(a.config.Checks), osName)
	}

	// Use a mutex to protect the shared maps
	var mu sync.Mutex
	// Use a WaitGroup to wait for all checks to complete
	var wg sync.WaitGroup
	// Limit concurrency to avoid overwhelming the system
	semaphore := make(chan struct{}, runtime.NumCPU())

	for checkName := range a.config.Checks {
		checkDef := a.config.Checks[checkName]

		// Get the rules for this OS
		rules := checkDef.CommandsForOS(osName)
		if len(rules) == 0 {
			if *debugMode {
				log.Printf("[DEBUG] Check %s not available for OS %s", checkName, osName)
			}
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			checkStart := time.Now()

			// Run all rules for this check
			var outputs []gitmdm.CommandOutput
			for _, rule := range rules {
				output := a.executeCheck(ctx, checkName, rule)
				outputs = append(outputs, output)
			}

			// Analyze all outputs to determine status
			status, reason, remediation := analyzer.DetermineOverallStatus(outputs)

			check := gitmdm.Check{
				Timestamp:   time.Now(), // Set the timestamp when the check was performed
				Outputs:     outputs,
				Status:      status,
				Reason:      reason,
				Remediation: remediation,
			}

			// Update shared state with mutex
			mu.Lock()
			checks[checkName] = check
			// Update counters based on status
			switch status {
			case statusPass:
				successCount++
				if *debugMode {
					log.Printf("[DEBUG] Check %s passed in %v: %s", checkName, time.Since(checkStart), reason)
				}
			case statusFail:
				failureCount++
				if *debugMode {
					log.Printf("[DEBUG] Check %s failed in %v: %s", checkName, time.Since(checkStart), reason)
				}
			default:
				// "n/a" - no counter update
			}
			mu.Unlock()
		}()
	}

	// Wait for all checks to complete
	wg.Wait()

	log.Printf("[INFO] Completed %d checks (%d successful, %d failed) in %v",
		successCount+failureCount, successCount, failureCount, time.Since(start))

	return checks
}

func (a *Agent) runSingleCheck(checkName string) string {
	// Use a 60-second timeout for single check execution
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	osName := runtime.GOOS

	checkDef, exists := a.config.Checks[checkName]
	if !exists {
		return fmt.Sprintf("Check '%s' not found", checkName)
	}

	// Get the rules for this OS
	rules := checkDef.CommandsForOS(osName)
	if len(rules) == 0 {
		return fmt.Sprintf("Check '%s' not available for %s", checkName, osName)
	}

	var outputBuilder strings.Builder
	var outputs []gitmdm.CommandOutput

	for i, rule := range rules {
		if i > 0 {
			outputBuilder.WriteString("\n\n=== Rule " + strconv.Itoa(i+1) + " ===\n")
		}

		// Display what we're checking
		if rule.File != "" {
			outputBuilder.WriteString("File: " + rule.File + "\n")
		} else if rule.Output != "" {
			outputBuilder.WriteString("Command: " + rule.Output + "\n")
		}

		output := a.executeCheck(ctx, checkName, rule)
		outputs = append(outputs, output)

		switch {
		case output.FileMissing:
			outputBuilder.WriteString("File not found\n")
		case output.Skipped:
			outputBuilder.WriteString("Command not available\n")
		default:
			if output.Stdout != "" {
				outputBuilder.WriteString(output.Stdout)
			}
			if output.Stderr != "" {
				outputBuilder.WriteString("\n--- STDERR ---\n" + output.Stderr)
			}
			if output.ExitCode != 0 {
				outputBuilder.WriteString(fmt.Sprintf("\n--- EXIT CODE: %d ---", output.ExitCode))
			}
		}

		// Show analysis for this specific rule
		if output.Failed {
			outputBuilder.WriteString(fmt.Sprintf("\n--- FAILED: %s ---", output.FailReason))
		} else if !output.Skipped && !output.FileMissing {
			outputBuilder.WriteString("\n--- PASSED ---")
		}
	}

	// Overall status analysis
	status, reason, remediation := analyzer.DetermineOverallStatus(outputs)

	outputBuilder.WriteString("\n\n=== OVERALL RESULT ===")
	switch status {
	case statusPass:
		outputBuilder.WriteString(fmt.Sprintf("\n✅ PASS: %s", reason))
	case statusFail:
		outputBuilder.WriteString(fmt.Sprintf("\n❌ FAIL: %s", reason))
		// Show command-specific remediation steps for failed checks
		if len(remediation) > 0 {
			outputBuilder.WriteString("\n\n=== HOW TO FIX ===")
			for i, step := range remediation {
				outputBuilder.WriteString(fmt.Sprintf("\n%d. %s", i+1, step))
			}
		}
	default:
		outputBuilder.WriteString(fmt.Sprintf("\n➖ NOT APPLICABLE: %s", reason))
	}

	return outputBuilder.String()
}

func (*Agent) systemUptime(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "openbsd", "netbsd", "dragonfly":
		cmd = exec.CommandContext(ctx, "uptime")
	case "solaris", "illumos":
		cmd = exec.CommandContext(ctx, "uptime")
	case osWindows:
		cmd = exec.CommandContext(ctx, wmicCmd, "os", wmicGetArg, "lastbootuptime")
	default:
		return "unsupported"
	}

	if output, err := cmd.Output(); err == nil {
		return strings.TrimSpace(string(output))
	}
	return "unavailable"
}

func (*Agent) cpuLoad(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case osLinux:
		cmd = exec.CommandContext(ctx, "cat", "/proc/loadavg")
	case "darwin", "freebsd", "openbsd", "netbsd", "dragonfly":
		cmd = exec.CommandContext(ctx, "sysctl", "-n", "vm.loadavg")
	case "solaris", "illumos":
		cmd = exec.CommandContext(ctx, "uptime")
	case osWindows:
		cmd = exec.CommandContext(ctx, wmicCmd, "cpu", wmicGetArg, "loadpercentage")
	default:
		return "unsupported"
	}

	if output, err := cmd.Output(); err == nil {
		result := strings.TrimSpace(string(output))
		// For Linux /proc/loadavg, extract just the three load averages
		if runtime.GOOS == osLinux {
			fields := strings.Fields(result)
			if len(fields) >= 3 {
				result = strings.Join(fields[:3], " ")
			}
		}
		// For uptime output on Solaris, extract just the load average part
		if (runtime.GOOS == "solaris" || runtime.GOOS == "illumos") && strings.Contains(result, "load average:") {
			parts := strings.Split(result, "load average:")
			if len(parts) > 1 {
				result = strings.TrimSpace(parts[1])
			}
		}
		return result
	}
	return "unavailable"
}

func (*Agent) loggedInUsers(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "openbsd", "netbsd", "dragonfly", "solaris", "illumos":
		cmd = exec.CommandContext(ctx, "who")
	case osWindows:
		cmd = exec.CommandContext(ctx, wmicCmd, "computersystem", wmicGetArg, "username")
	default:
		return "unsupported"
	}

	if output, err := cmd.Output(); err == nil {
		result := strings.TrimSpace(string(output))
		// Count unique users for Unix-like systems
		if runtime.GOOS != osWindows {
			lines := strings.Split(result, "\n")
			userMap := make(map[string]bool)
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					userMap[fields[0]] = true
				}
			}
			users := make([]string, 0, len(userMap))
			for user := range userMap {
				users = append(users, user)
			}
			if len(users) > 0 {
				return fmt.Sprintf("%d users: %s", len(users), strings.Join(users, ", "))
			}
			return "no users logged in"
		}
		return result
	}
	return "unavailable"
}

func (*Agent) osInfo(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case osLinux:
		// Try to get pretty name from os-release
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					name := strings.TrimPrefix(line, "PRETTY_NAME=")
					return strings.Trim(name, `"`)
				}
			}
		}
		// Fallback to uname
		cmd = exec.CommandContext(ctx, "uname", "-s")
	case osDarwin:
		cmd = exec.CommandContext(ctx, "sw_vers", "-productName")
	case osWindows:
		cmd = exec.CommandContext(ctx, wmicCmd, "os", wmicGetArg, "Caption", "/value")
	default:
		cmd = exec.CommandContext(ctx, "uname", "-s")
	}
	if cmd != nil {
		if output, err := cmd.Output(); err == nil {
			result := strings.TrimSpace(string(output))
			if runtime.GOOS == osWindows && strings.Contains(result, "Caption=") {
				result = strings.TrimPrefix(result, "Caption=")
			}
			if result != "" {
				return result
			}
		}
	}
	// Fallback to Go's runtime info
	return runtime.GOOS
}

func (*Agent) osVersion(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case osLinux:
		cmd = exec.CommandContext(ctx, "uname", "-r")
	case osDarwin:
		cmd = exec.CommandContext(ctx, "sw_vers", "-productVersion")
	case osWindows:
		cmd = exec.CommandContext(ctx, wmicCmd, "os", wmicGetArg, "Version", "/value")
	default:
		cmd = exec.CommandContext(ctx, "uname", "-r")
	}
	if output, err := cmd.Output(); err == nil {
		result := strings.TrimSpace(string(output))
		if runtime.GOOS == osWindows && strings.Contains(result, "Version=") {
			result = strings.TrimPrefix(result, "Version=")
		}
		if result != "" {
			return result
		}
	}
	return "unknown"
}

func darwinHardwareID() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	output, err := cmd.Output()
	if err != nil {
		if *debugMode {
			log.Printf("[DEBUG] Failed to get macOS hardware ID via ioreg: %v", err)
		}
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.Split(line, "\"")
			if len(parts) >= minUUIDParts {
				id := parts[3]
				if *debugMode {
					log.Printf("[DEBUG] Found macOS hardware UUID: %s", id)
				}
				return id
			}
		}
	}
	return ""
}

func linuxHardwareID() string {
	data, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err == nil {
		id := strings.TrimSpace(string(data))
		if *debugMode {
			log.Printf("[DEBUG] Found Linux hardware UUID from DMI: %s", id)
		}
		return id
	}

	data, err = os.ReadFile("/etc/machine-id")
	if err == nil {
		id := strings.TrimSpace(string(data))
		if *debugMode {
			log.Printf("[DEBUG] Found Linux machine ID: %s", id)
		}
		return id
	}

	if *debugMode {
		log.Print("[DEBUG] Failed to get Linux hardware ID from both DMI and machine-id")
	}
	return ""
}

func bsdHardwareID() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sysctl", "-n", "kern.hostuuid")
	output, err := cmd.Output()
	if err != nil {
		if *debugMode {
			log.Printf("[DEBUG] Failed to get BSD hardware ID via sysctl: %v", err)
		}
		return ""
	}
	id := strings.TrimSpace(string(output))
	if *debugMode {
		log.Printf("[DEBUG] Found BSD hardware UUID: %s", id)
	}
	return id
}

func solarisHardwareID() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "hostid")
	output, err := cmd.Output()
	if err != nil {
		if *debugMode {
			log.Printf("[DEBUG] Failed to get Solaris host ID: %v", err)
		}
		return ""
	}
	id := strings.TrimSpace(string(output))
	if *debugMode {
		log.Printf("[DEBUG] Found Solaris host ID: %s", id)
	}
	return id
}

func illumosHardwareID() string {
	// Try sysinfo first (Illumos specific)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sysinfo", "-p")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "UUID=") {
				id := strings.TrimPrefix(line, "UUID=")
				id = strings.TrimSpace(id)
				if *debugMode {
					log.Printf("[DEBUG] Found Illumos UUID: %s", id)
				}
				return id
			}
		}
	}
	// Fall back to hostid
	return solarisHardwareID()
}

func windowsHardwareID() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, wmicCmd, "csproduct", wmicGetArg, "UUID")
	output, err := cmd.Output()
	if err != nil {
		if *debugMode {
			log.Printf("[DEBUG] Failed to get Windows hardware ID via wmic: %v", err)
		}
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && trimmed != "UUID" {
			if *debugMode {
				log.Printf("[DEBUG] Found Windows hardware UUID: %s", trimmed)
			}
			return trimmed
		}
	}
	return ""
}

func hardwareID() string {
	start := time.Now()
	if *debugMode {
		log.Printf("[DEBUG] Detecting hardware ID for OS: %s", runtime.GOOS)
	}

	var id string
	switch runtime.GOOS {
	case osDarwin:
		id = darwinHardwareID()
	case osLinux:
		id = linuxHardwareID()
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		id = bsdHardwareID()
	case "solaris":
		id = solarisHardwareID()
	case "illumos":
		id = illumosHardwareID()
	case osWindows:
		id = windowsHardwareID()
	default:
		if *debugMode {
			log.Printf("[DEBUG] Unsupported OS for hardware ID detection: %s", runtime.GOOS)
		}
	}

	if id == "" {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
			if *debugMode {
				log.Printf("[DEBUG] Failed to get hostname for fallback ID: %v", err)
			}
		}
		hash := sha256.Sum256([]byte(hostname + runtime.GOOS))
		id = hex.EncodeToString(hash[:16])
		log.Printf("[WARN] Using fallback hardware ID based on hostname hash: %s", id)
	}

	if *debugMode {
		log.Printf("[DEBUG] Hardware ID detection completed in %v: %s", time.Since(start), id)
	}

	return id
}

// listAvailableChecks lists all available compliance checks for the current OS.
func (a *Agent) listAvailableChecks() {
	osName := runtime.GOOS

	log.Println("\n╭─────────────────────────────────────────────────╮")
	log.Println("│           Available Compliance Checks           │")
	log.Println("├─────────────────────────────────────────────────┤")
	log.Printf("│  Platform: %-36s │\n", osName)
	log.Println("╰─────────────────────────────────────────────────╯")
	log.Println()

	// List all checks available for this OS
	var availableChecks []string
	maxNameLen := 0
	for checkName := range a.config.Checks {
		checkDef := a.config.Checks[checkName]
		rules := checkDef.CommandsForOS(osName)
		if len(rules) > 0 {
			availableChecks = append(availableChecks, checkName)
			if len(checkName) > maxNameLen {
				maxNameLen = len(checkName)
			}
		}
	}

	// Sort checks alphabetically
	sort.Strings(availableChecks)

	// Display checks with descriptions from YAML
	for _, checkName := range availableChecks {
		checkDef := a.config.Checks[checkName]
		description, ok := checkDef["description"].(string)
		if !ok {
			description = ""
		}
		if description == "" {
			description = "Compliance check"
		}
		log.Printf("  %-*s  %s\n", maxNameLen, checkName, description)
	}

	log.Println()
	log.Println("Usage:")
	log.Println("  Run a single check:  agent -run <check_name>")
	log.Println("  Run all checks:      agent -run all")
	log.Println()
}

// CheckResult represents the results of running a security check.
type CheckResult struct {
	Status      string
	Reason      string
	Remediation []string
	Commands    []string
	Outputs     []gitmdm.CommandOutput
}

// CheckResultSummary contains summary stats for check execution.
type CheckResultSummary struct {
	PassCount int
	FailCount int
	NACount   int
}

// runAllChecksInteractive runs all available checks and displays results in a modern format.
func (a *Agent) runAllChecksInteractive() {
	// Enable quiet mode to suppress INFO logs during interactive display
	oldQuiet := quiet
	quiet = true
	defer func() { quiet = oldQuiet }()

	osName := runtime.GOOS
	fmt.Println("🔍 Running compliance checks...")
	fmt.Println()

	// Get all available checks for this OS
	var availableChecks []string
	for checkName := range a.config.Checks {
		checkDef := a.config.Checks[checkName]
		rules := checkDef.CommandsForOS(osName)
		if len(rules) > 0 {
			availableChecks = append(availableChecks, checkName)
		}
	}

	// Sort alphabetically for consistent output
	sort.Strings(availableChecks)

	// Execute all checks
	results, summary := a.executeAllChecks(availableChecks, osName)

	// Display results
	a.displayCheckResults(results, availableChecks, summary)
}

// executeAllChecks runs all specified checks and returns results and summary.
func (a *Agent) executeAllChecks(checkNames []string, osName string) (map[string]CheckResult, CheckResultSummary) {
	results := make(map[string]CheckResult)
	summary := CheckResultSummary{}
	// Use a reasonable timeout for all checks (5 minutes)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	for _, checkName := range checkNames {
		checkDef := a.config.Checks[checkName]
		rules := checkDef.CommandsForOS(osName)

		// Execute all rules for this check
		var outputs []gitmdm.CommandOutput
		for _, rule := range rules {
			output := a.executeCheck(ctx, checkName, rule)
			outputs = append(outputs, output)
		}

		// Analyze results
		status, reason, remediation := analyzer.DetermineOverallStatus(outputs)

		// Extract commands/files from outputs for display
		var commands []string
		for _, output := range outputs {
			if output.Command != "" {
				commands = append(commands, output.Command)
			} else if output.File != "" {
				commands = append(commands, "file: "+output.File)
			}
		}

		result := CheckResult{
			Status:      status,
			Reason:      reason,
			Remediation: remediation,
			Commands:    commands,
			Outputs:     outputs,
		}
		results[checkName] = result

		// Update summary
		switch result.Status {
		case statusPass:
			summary.PassCount++
		case statusFail:
			summary.FailCount++
		default:
			summary.NACount++
		}
	}

	return results, summary
}

// displayCheckResults shows the check results in a formatted way.
func (a *Agent) displayCheckResults(results map[string]CheckResult, finalOrder []string, summary CheckResultSummary) {
	fmt.Println()

	// In verbose mode, show all checks
	if *verbose {
		a.displayAllChecks(results, finalOrder, summary)
		return
	}

	// Normal mode - show summary and failures only
	if summary.FailCount > 0 {
		pluralS := ""
		if summary.FailCount != 1 {
			pluralS = "s"
		}
		fmt.Printf("⚠️  %d issue%s require attention\n", summary.FailCount, pluralS)
		fmt.Println()
		a.displayFailedChecks(results, finalOrder)
	} else {
		fmt.Println("✅ All compliance checks passed")
		fmt.Println()
	}

	// Show summary at the end
	fmt.Printf("Summary: %d passed, %d failed, %d not applicable\n",
		summary.PassCount, summary.FailCount, summary.NACount)
	fmt.Println()
}

// displayFailedOutput displays a single failed output with appropriate formatting.
func displayFailedOutput(idx int, output gitmdm.CommandOutput, totalOutputs int) {
	// If multiple commands were checked, number them
	if totalOutputs > 1 {
		fmt.Printf("      [Command %d of %d - FAILED]\n", idx+1, totalOutputs)
	}

	// Show command or file that was checked
	if output.Command != "" {
		fmt.Printf("      Command: %s\n", output.Command)
	} else if output.File != "" {
		fmt.Printf("      File: %s\n", output.File)
	}
	// Show why it failed
	if output.FailReason != "" {
		fmt.Printf("      Failure: %s\n", output.FailReason)
	}

	// Show relevant output (truncated for readability)
	if output.Stdout != "" {
		lines := strings.Split(output.Stdout, "\n")
		maxLines := maxDisplayLines
		if len(lines) > maxLines {
			fmt.Printf("      Output: %s\n", strings.Join(lines[:maxLines], "\n      "))
			fmt.Printf("      ... (output truncated, %d more lines)\n", len(lines)-maxLines)
		} else {
			fmt.Printf("      Output: %s\n", strings.ReplaceAll(output.Stdout, "\n", "\n      "))
		}
	}

	if output.Stderr != "" && output.Stderr != output.FailReason {
		fmt.Printf("      Error: %s\n", output.Stderr)
	}
}

// displayFailedChecks shows details for all failed checks.
func (*Agent) displayFailedChecks(results map[string]CheckResult, finalOrder []string) {
	// Get failed checks in order
	var failedChecks []string
	for _, checkName := range finalOrder {
		if result, exists := results[checkName]; exists && result.Status == "fail" {
			failedChecks = append(failedChecks, checkName)
		}
	}

	for index, checkName := range failedChecks {
		result := results[checkName]
		// Display single failed check inline
		displayName := strings.ReplaceAll(checkName, "_", " ")
		fmt.Printf("🔸 %s\n", displayName)
		fmt.Printf("   🐞 Problem: %s\n", result.Reason)

		// Show evidence - command and output for failed checks
		if len(result.Outputs) > 0 {
			fmt.Println("   💻 Evidence:")
			failedCount := 0
			for idx, output := range result.Outputs {
				// Skip outputs that didn't fail
				if !output.Failed {
					continue
				}
				failedCount++

				displayFailedOutput(idx, output, len(result.Outputs))
				// Add spacing between multiple failed commands
				if failedCount < len(result.Outputs) && len(result.Outputs) > 1 {
					for j := idx + 1; j < len(result.Outputs); j++ {
						if result.Outputs[j].Failed {
							fmt.Println()
							break
						}
					}
				}
			}
		}

		if len(result.Remediation) > 0 {
			fmt.Println()
			fmt.Println("   🔧 How to fix:")
			for j, step := range result.Remediation {
				fmt.Printf("      %d. %s\n", j+1, step)
			}
		}

		// Add spacing between issues (but not after the last one)
		if index < len(failedChecks)-1 {
			fmt.Println()
			fmt.Println("   ─────────────────────────")
			fmt.Println()
		}
	}
}

// displayAllChecks shows all checks in verbose mode.
// getStatusDisplay returns the icon and color text for a status.
func getStatusDisplay(status string) (icon, color string) {
	switch status {
	case statusPass:
		return "✅", "PASS"
	case statusFail:
		return "❌", "FAIL"
	default:
		return "➖", "N/A"
	}
}

// displayCommandOutput displays a single command output.
func displayCommandOutput(output gitmdm.CommandOutput, index, total int) {
	// Show command number if multiple
	if total > 1 {
		status := "OK"
		if output.Failed {
			status = "FAILED"
		} else if output.Skipped || output.FileMissing {
			status = "SKIPPED"
		}
		fmt.Printf("[Command %d of %d - %s]\n", index+1, total, status)
	}

	if output.Command != "" {
		fmt.Printf("Command: %s\n", output.Command)
	} else if output.File != "" {
		fmt.Printf("File: %s\n", output.File)
	}

	switch {
	case output.FileMissing:
		fmt.Println("Result: File not found")
	case output.Skipped:
		fmt.Println("Result: Command not available")
	default:
		displayOutputContent(output)
	}

	switch {
	case output.Failed:
		fmt.Printf("Status: FAILED - %s\n", output.FailReason)
	case output.Skipped, output.FileMissing:
		fmt.Println("Status: SKIPPED")
	default:
		fmt.Println("Status: OK")
	}
	fmt.Println()
}

// displayOutputContent displays the stdout/stderr content of a command.
func displayOutputContent(output gitmdm.CommandOutput) {
	if output.Stdout != "" {
		lines := strings.Split(strings.TrimRight(output.Stdout, "\n"), "\n")
		if len(lines) > maxVerboseLines {
			fmt.Printf("Output (%d lines, showing first 20):\n", len(lines))
			for i := range maxVerboseLines {
				fmt.Printf("  %s\n", lines[i])
			}
			fmt.Printf("  ... (%d more lines)\n", len(lines)-20)
		} else {
			fmt.Println("Output:")
			for _, line := range lines {
				fmt.Printf("  %s\n", line)
			}
		}
	}

	if output.Stderr != "" {
		fmt.Printf("Stderr: %s\n", output.Stderr)
	}

	if output.ExitCode != 0 {
		fmt.Printf("Exit Code: %d\n", output.ExitCode)
	}
}

// displayRemediation displays remediation steps for a failed check.
func displayRemediation(remediation []string) {
	if len(remediation) == 0 {
		return
	}
	fmt.Println("Remediation Steps:")
	for i, step := range remediation {
		fmt.Printf("  %d. %s\n", i+1, step)
	}
	fmt.Println()
}

// displayCheckSummary displays the summary of check results.
func displayCheckSummary(summary CheckResultSummary) {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println(" SUMMARY")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  Passed:         %d\n", summary.PassCount)
	fmt.Printf("  Failed:         %d\n", summary.FailCount)
	fmt.Printf("  Not Applicable: %d\n", summary.NACount)
	fmt.Printf("  Total:          %d\n", summary.PassCount+summary.FailCount+summary.NACount)
	fmt.Println()
}

func (*Agent) displayAllChecks(results map[string]CheckResult, checkOrder []string, summary CheckResultSummary) {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println(" COMPLIANCE CHECK RESULTS (Verbose Mode)")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	for _, checkName := range checkOrder {
		result, exists := results[checkName]
		if !exists {
			continue
		}

		// Display check header inline
		statusIcon, statusColor := getStatusDisplay(result.Status)
		displayName := strings.ToUpper(strings.ReplaceAll(checkName, "_", " "))
		fmt.Printf("%s %s [%s]\n", statusIcon, displayName, statusColor)
		fmt.Println("───────────────────────────────────────────────────────────────")

		// Show all command outputs
		for i, output := range result.Outputs {
			displayCommandOutput(output, i, len(result.Outputs))
		}

		// Show remediation if failed
		if result.Status == statusFail {
			displayRemediation(result.Remediation)
		}

		fmt.Println()
	}

	displayCheckSummary(summary)
}
