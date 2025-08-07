// Package main implements the gitMDM agent that collects compliance data.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gitmdm/internal/analyzer"
	"gitmdm/internal/config"
	"gitmdm/internal/gitmdm"

	"github.com/codeGROOVE-dev/retry"

	"gopkg.in/yaml.v3"
)

const (
	// Command execution timeout.
	commandTimeout = 10 * time.Second
	// Maximum output size to prevent memory exhaustion.
	maxOutputSize = 92160 // 90KB limit (matching server)
	// Maximum log output length for readability.
	maxLogLength = 200
	// Minimum parts required for IOPlatformUUID parsing.
	minUUIDParts = 4
	// Retry configuration.
	maxRetries     = 3
	initialBackoff = 1 * time.Second
	maxBackoff     = 2 * time.Minute // Wait up to 2 minutes with exponential backoff
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
	debug      = flag.Bool("debug", false, "Enable debug logging")
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

func main() {
	flag.Parse()

	var cfg config.Config
	if err := yaml.Unmarshal(checksConfig, &cfg); err != nil {
		log.Fatalf("Failed to parse checks config: %v", err)
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

	agent := &Agent{
		config:     &cfg,
		hardwareID: hardwareID(),
		hostname:   hostname,
		user:       user,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
		failedReports: make(chan gitmdm.DeviceReport, failedReportsQueueSize),
	}

	// Handle --list flag
	if *listChecks {
		agent.listAvailableChecks()
		return
	}

	// Handle --install flag
	if *install {
		if *server == "" || *join == "" {
			log.Fatal("--server and --join flags are required for installation")
		}

		// Set up agent configuration for verification
		agent.serverURL = strings.TrimSuffix(*server, "/")
		agent.joinKey = *join

		// Verify server connection and join key by sending a test report
		log.Println("Verifying server connection and join key...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Run checks and attempt to report to server
		report := gitmdm.DeviceReport{
			HardwareID:    agent.hardwareID,
			Hostname:      agent.hostname,
			User:          agent.user,
			Timestamp:     time.Now(),
			Checks:        agent.runAllChecks(ctx),
			SystemUptime:  agent.systemUptime(ctx),
			CPULoad:       agent.cpuLoad(ctx),
			LoggedInUsers: agent.loggedInUsers(ctx),
		}

		if err := agent.sendReport(ctx, report); err != nil {
			cancel()
			log.Fatalf("Failed to verify server connection: %v\nPlease check your --server and --join parameters", err) //nolint:gocritic // exitAfterDefer
		}

		log.Println("✓ Server connection verified successfully")
		log.Printf("✓ Device registered as: %s (%s)", agent.hostname, agent.hardwareID)

		// Now proceed with installation
		if err := installAgent(*server, *join); err != nil {
			log.Fatalf("Installation failed: %v", err)
		}
		log.Println("✓ Agent installed successfully and will run automatically at startup")
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

	// Try to load config file if server/join not provided via flags
	if *server == "" || *join == "" {
		cfg, err := loadConfig()
		if err != nil {
			// Config file doesn't exist or is invalid
			if *server == "" {
				log.Fatal("Server URL is required (use --server flag or install agent with --install)")
			}
			if *join == "" {
				log.Fatal("Join key is required (use --join flag or install agent with --install)")
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

	agent.serverURL = strings.TrimSuffix(*server, "/")
	agent.joinKey = *join

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	log.Printf("[INFO] Agent started. Hardware ID: %s, Hostname: %s, User: %s", agent.hardwareID, agent.hostname, agent.user)
	log.Printf("[INFO] Reporting to server: %s every %v", agent.serverURL, *interval)
	log.Printf("[INFO] Retry configuration: max_retries=%d, initial_backoff=%v, max_backoff=%v", maxRetries, initialBackoff, maxBackoff)

	// Start failed reports processor
	go agent.processFailedReports(ctx)

	// Initial report
	agent.reportToServer(ctx)

	for {
		select {
		case <-ticker.C:
			agent.reportToServer(ctx)
		case <-sigChan:
			log.Println("Shutting down agent...")
			return
		case <-ctx.Done():
			return
		}
	}
}

func (a *Agent) reportToServer(ctx context.Context) {
	start := time.Now()

	// Collect system metrics (not persisted to git)
	uptime := a.systemUptime(ctx)
	cpuLoad := a.cpuLoad(ctx)
	loggedInUsers := a.loggedInUsers(ctx)

	report := gitmdm.DeviceReport{
		HardwareID:    a.hardwareID,
		Hostname:      a.hostname,
		User:          a.user,
		Timestamp:     time.Now(),
		Checks:        a.runAllChecks(ctx),
		SystemUptime:  uptime,
		CPULoad:       cpuLoad,
		LoggedInUsers: loggedInUsers,
	}

	if *debug {
		log.Printf("[DEBUG] Generated report with %d checks in %v", len(report.Checks), time.Since(start))
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
		log.Printf("[ERROR] Failed to send report after %d retries: %v", maxRetries, err)
		// Queue for later retry if queue not full
		select {
		case a.failedReports <- report:
			log.Print("[INFO] Report queued for retry processing")
		default:
			log.Print("[WARN] Failed reports queue is full, dropping report")
		}
		return
	}

	if *debug {
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
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("[WARN] Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		// Read response body for debugging (limit to 256 bytes)
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
		if err != nil {
			return fmt.Errorf("server returned status %d (failed to read body: %w)", resp.StatusCode, err)
		}
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(bodyBytes))
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

	if *debug {
		log.Printf("[DEBUG] Running %d checks for OS: %s", len(a.config.Checks), osName)
	}

	for checkName := range a.config.Checks {
		checkDef := a.config.Checks[checkName]
		checkStart := time.Now()

		// Get the rules for this OS
		rules := checkDef.CommandsForOS(osName)
		if len(rules) == 0 {
			if *debug {
				log.Printf("[DEBUG] Check %s not available for OS %s", checkName, osName)
			}
			continue
		}

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
		checks[checkName] = check

		// Update counters based on status
		switch status {
		case statusPass:
			successCount++
			if *debug {
				log.Printf("[DEBUG] Check %s passed in %v: %s", checkName, time.Since(checkStart), reason)
			}
		case statusFail:
			failureCount++
			if *debug {
				log.Printf("[DEBUG] Check %s failed in %v: %s", checkName, time.Since(checkStart), reason)
			}
		default:
			// "n/a" - no counter update
		}
	}

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
	case "windows":
		cmd = exec.CommandContext(ctx, "wmic", "os", "get", "lastbootuptime")
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
	case "linux":
		cmd = exec.CommandContext(ctx, "cat", "/proc/loadavg")
	case "darwin", "freebsd", "openbsd", "netbsd", "dragonfly":
		cmd = exec.CommandContext(ctx, "sysctl", "-n", "vm.loadavg")
	case "solaris", "illumos":
		cmd = exec.CommandContext(ctx, "uptime")
	case "windows":
		cmd = exec.CommandContext(ctx, "wmic", "cpu", "get", "loadpercentage")
	default:
		return "unsupported"
	}

	if output, err := cmd.Output(); err == nil {
		result := strings.TrimSpace(string(output))
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
	case "windows":
		cmd = exec.CommandContext(ctx, "wmic", "computersystem", "get", "username")
	default:
		return "unsupported"
	}

	if output, err := cmd.Output(); err == nil {
		result := strings.TrimSpace(string(output))
		// Count unique users for Unix-like systems
		if runtime.GOOS != "windows" {
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

func darwinHardwareID() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	output, err := cmd.Output()
	if err != nil {
		if *debug {
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
				if *debug {
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
		if *debug {
			log.Printf("[DEBUG] Found Linux hardware UUID from DMI: %s", id)
		}
		return id
	}

	data, err = os.ReadFile("/etc/machine-id")
	if err == nil {
		id := strings.TrimSpace(string(data))
		if *debug {
			log.Printf("[DEBUG] Found Linux machine ID: %s", id)
		}
		return id
	}

	if *debug {
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
		if *debug {
			log.Printf("[DEBUG] Failed to get BSD hardware ID via sysctl: %v", err)
		}
		return ""
	}
	id := strings.TrimSpace(string(output))
	if *debug {
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
		if *debug {
			log.Printf("[DEBUG] Failed to get Solaris host ID: %v", err)
		}
		return ""
	}
	id := strings.TrimSpace(string(output))
	if *debug {
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
				if *debug {
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
	cmd := exec.CommandContext(ctx, "wmic", "csproduct", "get", "UUID")
	output, err := cmd.Output()
	if err != nil {
		if *debug {
			log.Printf("[DEBUG] Failed to get Windows hardware ID via wmic: %v", err)
		}
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && trimmed != "UUID" {
			if *debug {
				log.Printf("[DEBUG] Found Windows hardware UUID: %s", trimmed)
			}
			return trimmed
		}
	}
	return ""
}

func hardwareID() string {
	start := time.Now()
	if *debug {
		log.Printf("[DEBUG] Detecting hardware ID for OS: %s", runtime.GOOS)
	}

	var id string
	switch runtime.GOOS {
	case "darwin":
		id = darwinHardwareID()
	case "linux":
		id = linuxHardwareID()
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		id = bsdHardwareID()
	case "solaris":
		id = solarisHardwareID()
	case "illumos":
		id = illumosHardwareID()
	case "windows":
		id = windowsHardwareID()
	default:
		if *debug {
			log.Printf("[DEBUG] Unsupported OS for hardware ID detection: %s", runtime.GOOS)
		}
	}

	if id == "" {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
			if *debug {
				log.Printf("[DEBUG] Failed to get hostname for fallback ID: %v", err)
			}
		}
		hash := sha256.Sum256([]byte(hostname + runtime.GOOS))
		id = hex.EncodeToString(hash[:16])
		log.Printf("[WARN] Using fallback hardware ID based on hostname hash: %s", id)
	}

	if *debug {
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
		description := checkDef.Description
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

// print is a helper for interactive mode output without timestamps.
func printLine(format string, args ...any) {
	if format == "" {
		fmt.Println() //nolint:forbidigo // Interactive mode requires direct output
	} else {
		fmt.Printf(format+"\n", args...) //nolint:forbidigo // Interactive mode requires direct output
	}
}

// runAllChecksInteractive runs all available checks and displays results in a modern format.
func (a *Agent) runAllChecksInteractive() {
	// Enable quiet mode to suppress INFO logs during interactive display
	oldQuiet := quiet
	quiet = true
	defer func() { quiet = oldQuiet }()

	osName := runtime.GOOS
	printLine("🔍 Running compliance checks...")
	printLine("")

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
	printLine("")

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
		printLine("⚠️  %d issue%s require attention", summary.FailCount, pluralS)
		printLine("")
		a.displayFailedChecks(results, finalOrder)
	} else {
		printLine("✅ All compliance checks passed")
		printLine("")
	}

	// Show summary at the end
	printLine("Summary: %d passed, %d failed, %d not applicable",
		summary.PassCount, summary.FailCount, summary.NACount)
	printLine("")
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
		printLine("🔸 %s", displayName)
		printLine("   🐞 Problem: %s", result.Reason)

		// Show evidence - command and output for failed checks
		if len(result.Outputs) > 0 {
			printLine("   💻 Evidence:")
			for _, output := range result.Outputs {
				// Skip outputs that didn't fail
				if !output.Failed {
					continue
				}

				// Show command or file that was checked
				if output.Command != "" {
					printLine("      Command: %s", output.Command)
				} else if output.File != "" {
					printLine("      File: %s", output.File)
				}

				// Show relevant output (truncated for readability)
				if output.Stdout != "" {
					lines := strings.Split(output.Stdout, "\n")
					maxLines := maxDisplayLines
					if len(lines) > maxLines {
						printLine("      Output: %s", strings.Join(lines[:maxLines], "\n      "))
						printLine("      ... (output truncated, %d more lines)", len(lines)-maxLines)
					} else {
						printLine("      Output: %s", strings.ReplaceAll(output.Stdout, "\n", "\n      "))
					}
				}

				if output.Stderr != "" && output.Stderr != output.FailReason {
					printLine("      Error: %s", output.Stderr)
				}
			}
		}

		if len(result.Remediation) > 0 {
			printLine("")
			printLine("   🔧 How to fix:")
			for j, step := range result.Remediation {
				printLine("      %d. %s", j+1, step)
			}
		}

		// Add spacing between issues (but not after the last one)
		if index < len(failedChecks)-1 {
			printLine("")
			printLine("   ─────────────────────────")
			printLine("")
		}
	}
}

// displayAllChecks shows all checks in verbose mode.
func (*Agent) displayAllChecks(results map[string]CheckResult, checkOrder []string, summary CheckResultSummary) {
	printLine("═══════════════════════════════════════════════════════════════")
	printLine(" COMPLIANCE CHECK RESULTS (Verbose Mode)")
	printLine("═══════════════════════════════════════════════════════════════")
	printLine("")

	for _, checkName := range checkOrder {
		result, exists := results[checkName]
		if !exists {
			continue
		}

		// Check header with status icon
		var statusIcon string
		var statusColor string
		switch result.Status {
		case statusPass:
			statusIcon = "✅"
			statusColor = "PASS"
		case statusFail:
			statusIcon = "❌"
			statusColor = "FAIL"
		default:
			statusIcon = "➖"
			statusColor = "N/A"
		}

		displayName := strings.ToUpper(strings.ReplaceAll(checkName, "_", " "))
		printLine("%s %s [%s]", statusIcon, displayName, statusColor)
		printLine("───────────────────────────────────────────────────────────────")

		// Show all command outputs
		for _, output := range result.Outputs {
			if output.Command != "" {
				printLine("Command: %s", output.Command)
			} else if output.File != "" {
				printLine("File: %s", output.File)
			}

			switch {
			case output.FileMissing:
				printLine("Result: File not found")
			case output.Skipped:
				printLine("Result: Command not available")
			default:
				// Show output
				if output.Stdout != "" {
					lines := strings.Split(strings.TrimRight(output.Stdout, "\n"), "\n")
					if len(lines) > maxVerboseLines {
						printLine("Output (%d lines, showing first 20):", len(lines))
						for i := range maxVerboseLines {
							printLine("  %s", lines[i])
						}
						printLine("  ... (%d more lines)", len(lines)-20)
					} else {
						printLine("Output:")
						for _, line := range lines {
							printLine("  %s", line)
						}
					}
				}

				if output.Stderr != "" {
					printLine("Stderr: %s", output.Stderr)
				}

				if output.ExitCode != 0 {
					printLine("Exit Code: %d", output.ExitCode)
				}
			}

			if output.Failed {
				printLine("Status: FAILED - %s", output.FailReason)
			} else {
				printLine("Status: OK")
			}
			printLine("")
		}

		// Show remediation if failed
		if result.Status == statusFail && len(result.Remediation) > 0 {
			printLine("Remediation Steps:")
			for i, step := range result.Remediation {
				printLine("  %d. %s", i+1, step)
			}
			printLine("")
		}

		printLine("")
	}

	// Summary at the end
	printLine("═══════════════════════════════════════════════════════════════")
	printLine(" SUMMARY")
	printLine("═══════════════════════════════════════════════════════════════")
	printLine("  Passed:         %d", summary.PassCount)
	printLine("  Failed:         %d", summary.FailCount)
	printLine("  Not Applicable: %d", summary.NACount)
	printLine("  Total:          %d", summary.PassCount+summary.FailCount+summary.NACount)
	printLine("")
}
