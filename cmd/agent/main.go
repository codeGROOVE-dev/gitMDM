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
	"strings"
	"syscall"
	"time"

	"gitmdm/cmd/agent/analyzer"
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
	quiet      = false // Set to true to suppress INFO logs (used for interactive mode)
)

// ChecksConfig holds the configuration for compliance checks.
type ChecksConfig struct {
	Checks map[string]CheckDefinition `yaml:"checks"`
}

// CheckDefinition holds commands and remediation steps for a check.
type CheckDefinition struct {
	Commands    map[string][]string `yaml:"commands"`
	Remediation map[string][]string `yaml:"remediation"`
}

// Agent represents the gitMDM agent that collects compliance data.
type Agent struct {
	config        *ChecksConfig
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

	var config ChecksConfig
	if err := yaml.Unmarshal(checksConfig, &config); err != nil {
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
		config:     &config,
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

	if *server == "" {
		log.Fatal("Server URL is required (use --server flag)")
	}

	if *join == "" {
		log.Fatal("Join key is required when using --server (use --join flag)")
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

	err := retry.Do(func() error {
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
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 256))
		if err != nil {
			return fmt.Errorf("server returned status %d (failed to read body: %v)", resp.StatusCode, err)
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
					// Retry failed report inline
					log.Printf("[INFO] Retrying failed report for device %s", report.HardwareID)
					err := retry.Do(func() error {
						return a.sendReport(ctx, report)
					}, retry.Attempts(maxRetries), retry.DelayType(retry.FullJitterBackoffDelay), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff))

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
				default:
					// No more reports to process
					goto nextTick
				}
			}
		nextTick:
		}
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

	for checkName, checkDef := range a.config.Checks {
		checkStart := time.Now()
		var commands []string

		// First check exact OS match
		if cmds, exists := checkDef.Commands[osName]; exists {
			commands = cmds
		} else {
			// Check for comma-separated OS lists
			found := false
			for osListKey, cmds := range checkDef.Commands {
				osList := strings.Split(osListKey, ",")
				for _, osItem := range osList {
					if strings.TrimSpace(osItem) == osName {
						commands = cmds
						found = true
						break
					}
				}
				if found {
					break
				}
			}

			// Finally check for "all"
			if !found {
				cmds, exists := checkDef.Commands["all"]
				if !exists {
					if *debug {
						log.Printf("[DEBUG] Check %s not available for OS %s", checkName, osName)
					}
					continue
				}
				commands = cmds
			}
		}

		// Run all commands for this check
		var outputs []gitmdm.CommandOutput
		for _, command := range commands {
			output := a.executeCommandWithPipes(ctx, checkName, command)
			outputs = append(outputs, output)
		}

		// Analyze all outputs to determine status
		status, reason, remediation := a.analyzeCheckOutputs(checkName, osName, outputs)

		// If no remediation from analyzer and check failed, use YAML remediation
		if status == "fail" && len(remediation) == 0 {
			if steps, exists := checkDef.Remediation[osName]; exists {
				remediation = steps
			}
		}

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
		case "pass":
			successCount++
			if *debug {
				log.Printf("[DEBUG] Check %s passed in %v: %s", checkName, time.Since(checkStart), reason)
			}
		case "fail":
			failureCount++
			if *debug {
				log.Printf("[DEBUG] Check %s failed in %v: %s", checkName, time.Since(checkStart), reason)
			}
			// "n/a" - no counter update
		}
	}

	log.Printf("[INFO] Completed %d checks (%d successful, %d failed) in %v",
		successCount+failureCount, successCount, failureCount, time.Since(start))

	return checks
}

// analyzeCheckOutputs analyzes all command outputs for a check and determines status.
// Returns status ("pass", "fail", "n/a"), a reason, and command-specific remediation steps.
// For most checks: If ANY command passes, the check passes.
// For screen_lock: ALL commands must pass for the check to pass (SOC 2 requirement).
func (a *Agent) analyzeCheckOutputs(checkName string, osName string, outputs []gitmdm.CommandOutput) (string, string, []string) {
	if len(outputs) == 0 {
		return "n/a", "No commands to execute", nil
	}

	var passReasons []string
	var failReasons []string
	var remediation []string
	hasPass := false
	hasFail := false
	allNA := true

	for _, output := range outputs {
		// Analyze this specific command output
		result := analyzer.AnalyzeCheck(checkName, osName, output.Command, output.Stdout, output.Stderr, output.ExitCode)

		switch result.Status {
		case "pass":
			hasPass = true
			allNA = false
			passReasons = append(passReasons, result.Description)
			if *debug {
				log.Printf("[DEBUG] Check %s command '%s' passed: %s", checkName, output.Command, result.Description)
			}
		case "fail":
			hasFail = true
			allNA = false
			failReasons = append(failReasons, result.Description)
			// Collect command-specific remediation
			if len(result.Remediation) > 0 {
				remediation = append(remediation, result.Remediation...)
			}
			if *debug {
				log.Printf("[DEBUG] Check %s command '%s' failed: %s", checkName, output.Command, result.Description)
			}
		default: // "n/a"
			if *debug {
				log.Printf("[DEBUG] Check %s command '%s' n/a: %s", checkName, output.Command, result.Description)
			}
		}
	}

	// Special handling for screen_lock - ALL checks must pass for SOC 2 compliance
	if checkName == "screen_lock" {
		// If ANY check failed, the whole check fails
		if hasFail {
			if len(failReasons) == 1 {
				return "fail", failReasons[0], remediation
			}
			return "fail", strings.Join(failReasons, "; "), remediation
		}
		// All must pass (or be n/a)
		if hasPass && !hasFail {
			if len(passReasons) == 1 {
				return "pass", passReasons[0], nil
			}
			return "pass", "Screen lock properly configured", nil
		}
		// If all are N/A
		if allNA {
			return "n/a", "", nil
		}
	}

	// Default logic for other checks: If ANY command passes, the check passes
	if hasPass {
		if len(passReasons) > 0 {
			return "pass", passReasons[0], nil
		}
		return "pass", "", nil
	}

	// If all are N/A, return n/a with empty reason
	if allNA {
		return "n/a", "", nil
	}

	// Otherwise, it failed - combine all failure reasons
	if len(failReasons) == 1 {
		return "fail", failReasons[0], remediation
	}
	return "fail", strings.Join(failReasons, "; "), remediation
}

func (a *Agent) runSingleCheck(checkName string) string {
	osName := runtime.GOOS

	checkDef, exists := a.config.Checks[checkName]
	if !exists {
		return fmt.Sprintf("Check '%s' not found", checkName)
	}

	var commands []string
	// First check exact OS match
	if cmds, exists := checkDef.Commands[osName]; exists {
		commands = cmds
	} else {
		// Check for comma-separated OS lists
		found := false
		for osListKey, cmds := range checkDef.Commands {
			osList := strings.Split(osListKey, ",")
			for _, osItem := range osList {
				if strings.TrimSpace(osItem) == osName {
					commands = cmds
					found = true
					break
				}
			}
			if found {
				break
			}
		}

		// Finally check for "all"
		if !found {
			cmds, exists := checkDef.Commands["all"]
			if !exists {
				return fmt.Sprintf("Check '%s' not available for %s", checkName, osName)
			}
			commands = cmds
		}
	}

	var outputBuilder strings.Builder
	var outputs []gitmdm.CommandOutput

	for i, command := range commands {
		if i > 0 {
			outputBuilder.WriteString("\n\n=== Command " + fmt.Sprintf("%d", i+1) + " ===\n")
		}
		outputBuilder.WriteString("Command: " + command + "\n")

		check := a.executeCommandWithPipes(context.Background(), checkName, command)
		outputs = append(outputs, check)

		if check.Stdout != "" {
			outputBuilder.WriteString(check.Stdout)
		}
		if check.Stderr != "" {
			outputBuilder.WriteString("\n--- STDERR ---\n" + check.Stderr)
		}
		if check.ExitCode != 0 {
			outputBuilder.WriteString(fmt.Sprintf("\n--- EXIT CODE: %d ---", check.ExitCode))
		}

		// Analyze this specific command
		result := analyzer.AnalyzeCheck(checkName, osName, command, check.Stdout, check.Stderr, check.ExitCode)
		outputBuilder.WriteString(fmt.Sprintf("\n--- ANALYSIS: %s - %s ---", result.Status, result.Description))
	}

	// Overall status analysis
	status, reason, remediation := a.analyzeCheckOutputs(checkName, osName, outputs)

	// If no remediation from analyzer and check failed, use YAML remediation
	if status == "fail" && len(remediation) == 0 {
		if steps, exists := checkDef.Remediation[osName]; exists {
			remediation = steps
		}
	}

	outputBuilder.WriteString("\n\n=== OVERALL RESULT ===")
	switch status {
	case "pass":
		outputBuilder.WriteString(fmt.Sprintf("\n✅ PASS: %s", reason))
	case "fail":
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
			log.Printf("[DEBUG] Failed to get Solaris/illumos host ID: %v", err)
		}
		return ""
	}
	id := strings.TrimSpace(string(output))
	if *debug {
		log.Printf("[DEBUG] Found Solaris/illumos host ID: %s", id)
	}
	return id
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
	case "solaris", "illumos":
		id = solarisHardwareID()
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

// listAvailableChecks lists all available compliance checks for the current OS
func (a *Agent) listAvailableChecks() {
	osName := runtime.GOOS

	log.Println("\n╭─────────────────────────────────────────────────╮")
	log.Println("│           Available Compliance Checks           │")
	log.Println("├─────────────────────────────────────────────────┤")
	log.Printf("│  Platform: %-36s │\n", osName)
	log.Println("╰─────────────────────────────────────────────────╯")
	log.Println()

	// Categories for organization
	categories := map[string][]string{
		"🔒 Security": {"disk_encryption", "firewall", "app_firewall", "screen_lock", "auto_login", "password_policy", "antivirus"},
		"🔄 System":   {"software_updates", "system_info", "hostname", "uname"},
		"👥 Access":   {"users", "network"},
	}

	// Order to display categories
	categoryOrder := []string{"🔒 Security", "🔄 System", "👥 Access"}

	for _, category := range categoryOrder {
		checks := categories[category]
		log.Printf("%s\n", category)
		log.Println(strings.Repeat("─", 50))

		for _, checkName := range checks {
			if checkDef, exists := a.config.Checks[checkName]; exists {
				// Check if available for this OS
				available := false
				if _, exists := checkDef.Commands[osName]; exists {
					available = true
				} else if _, exists := checkDef.Commands["all"]; exists {
					available = true
				} else {
					// Check comma-separated OS lists
					for osListKey := range checkDef.Commands {
						osList := strings.Split(osListKey, ",")
						for _, osItem := range osList {
							if strings.TrimSpace(osItem) == osName {
								available = true
								break
							}
						}
						if available {
							break
						}
					}
				}

				if available {
					// Get description based on check type
					description := getCheckDescription(checkName)
					log.Printf("  %-20s %s\n", checkName, description)
				}
			}
		}
		log.Println()
	}

	log.Println("Usage:")
	log.Println("  Run a single check:  agent -run <check_name>")
	log.Println("  Run all checks:      agent -run all")
	log.Println()
}

// getCheckDescription returns a human-friendly description for each check
func getCheckDescription(checkName string) string {
	descriptions := map[string]string{
		"disk_encryption":  "Verify disk encryption status",
		"firewall":         "Check network firewall configuration",
		"app_firewall":     "Check application firewall (macOS)",
		"screen_lock":      "Verify screen lock settings",
		"auto_login":       "Check for automatic login",
		"password_policy":  "Review password policy configuration",
		"antivirus":        "Detect antivirus software",
		"software_updates": "Check for pending system updates",
		"system_info":      "Gather system information",
		"hostname":         "Display system hostname",
		"uname":            "Show system version details",
		"users":            "List system users",
		"network":          "Display network configuration",
	}

	if desc, exists := descriptions[checkName]; exists {
		return desc
	}
	return "System compliance check"
}

// CheckResult represents the results of running a security check.
type CheckResult struct {
	Status      string
	Reason      string
	Remediation []string
	Commands    []string
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
	log.Println("🔍 Running security checks...")
	log.Println()

	// Get checks to run in proper order
	var availableChecks []string
	for checkName, checkDef := range a.config.Checks {
		if a.isCheckAvailable(checkDef, osName) {
			availableChecks = append(availableChecks, checkName)
		}
	}
	finalOrder := a.orderChecks(availableChecks)

	// Execute all checks
	results, summary := a.executeAllChecks(finalOrder, osName)

	// Display results
	a.displayCheckResults(results, finalOrder, summary)
}

// isCheckAvailable determines if a check is available for the given OS.
func (*Agent) isCheckAvailable(checkDef CheckDefinition, osName string) bool {
	if _, exists := checkDef.Commands[osName]; exists {
		return true
	}
	if _, exists := checkDef.Commands["all"]; exists {
		return true
	}

	// Check comma-separated OS lists
	for osListKey := range checkDef.Commands {
		osList := strings.Split(osListKey, ",")
		for _, osItem := range osList {
			if strings.TrimSpace(osItem) == osName {
				return true
			}
		}
	}
	return false
}

// orderChecks sorts checks into preferred execution order.
func (*Agent) orderChecks(availableChecks []string) []string {
	checkOrder := []string{
		"disk_encryption", "firewall", "app_firewall", "screen_lock", "auto_login",
		"password_policy", "antivirus", "software_updates",
		"system_info", "hostname", "uname", "users", "network",
	}

	var finalOrder []string
	for _, check := range checkOrder {
		for _, available := range availableChecks {
			if check == available {
				finalOrder = append(finalOrder, check)
				break
			}
		}
	}
	return finalOrder
}

// executeAllChecks runs all specified checks and returns results and summary.
func (a *Agent) executeAllChecks(checkNames []string, osName string) (map[string]CheckResult, CheckResultSummary) {
	results := make(map[string]CheckResult)
	summary := CheckResultSummary{}

	for _, checkName := range checkNames {
		result := a.executeSingleCheck(checkName, osName)
		results[checkName] = result

		// Update summary
		switch result.Status {
		case "pass":
			summary.PassCount++
		case "fail":
			summary.FailCount++
		default:
			summary.NACount++
		}
	}

	return results, summary
}

// executeSingleCheck executes a single check and returns the result.
func (a *Agent) executeSingleCheck(checkName, osName string) CheckResult {
	checkDef := a.config.Checks[checkName]
	commands := a.getCommandsForOS(checkDef, osName)

	// Execute commands
	var outputs []gitmdm.CommandOutput
	for _, command := range commands {
		output := a.executeCommandWithPipes(context.Background(), checkName, command)
		outputs = append(outputs, output)
	}

	// Analyze results
	status, reason, remediation := a.analyzeCheckOutputs(checkName, osName, outputs)

	// Use YAML remediation if analyzer didn't provide any
	if status == "fail" && len(remediation) == 0 {
		if steps, exists := checkDef.Remediation[osName]; exists {
			remediation = steps
		}
	}

	return CheckResult{
		Status:      status,
		Reason:      reason,
		Remediation: remediation,
		Commands:    commands,
	}
}

// getCommandsForOS gets the appropriate commands for the given OS.
func (*Agent) getCommandsForOS(checkDef CheckDefinition, osName string) []string {
	if cmds, exists := checkDef.Commands[osName]; exists {
		return cmds
	}
	if cmds, exists := checkDef.Commands["all"]; exists {
		return cmds
	}

	// Check comma-separated OS lists
	for osListKey, cmds := range checkDef.Commands {
		osList := strings.Split(osListKey, ",")
		for _, osItem := range osList {
			if strings.TrimSpace(osItem) == osName {
				return cmds
			}
		}
	}
	return nil
}

// displayCheckResults shows the check results in a formatted way.
func (a *Agent) displayCheckResults(results map[string]CheckResult, finalOrder []string, summary CheckResultSummary) {
	log.Println()

	if summary.FailCount > 0 {
		pluralS := ""
		if summary.FailCount != 1 {
			pluralS = "s"
		}
		log.Printf("⚠️  %d issue%s require attention\n\n", summary.FailCount, pluralS)
		a.displayFailedChecks(results, finalOrder)
	} else {
		log.Println("✅ All systems secure")
		log.Println()
	}

	// Only show passed checks if there are no failures
	if summary.FailCount == 0 && summary.PassCount > 0 {
		pluralS := ""
		if summary.PassCount != 1 {
			pluralS = "s"
		}
		log.Printf("✅ %d check%s passed\n", summary.PassCount, pluralS)
	}

	log.Println()
}

// displayFailedChecks shows details for all failed checks.
func (a *Agent) displayFailedChecks(results map[string]CheckResult, finalOrder []string) {
	// Get failed checks in order
	var failedChecks []string
	for _, checkName := range finalOrder {
		if result, exists := results[checkName]; exists && result.Status == "fail" {
			failedChecks = append(failedChecks, checkName)
		}
	}

	for i, checkName := range failedChecks {
		result := results[checkName]
		// Display single failed check inline
		displayName := strings.ReplaceAll(checkName, "_", " ")
		log.Printf("🔸 %s\n", displayName)
		log.Printf("   🐞 Problem: %s\n", result.Reason)
		if len(result.Commands) > 0 {
			log.Printf("   💻 Evidence: %s\n", strings.Join(result.Commands, " && "))
		}
		if len(result.Remediation) > 0 {
			log.Printf("\n   🔧 How to fix:\n")
			for j, step := range result.Remediation {
				log.Printf("      %d. %s\n", j+1, step)
			}
		}

		// Add spacing between issues (but not after the last one)
		if i < len(failedChecks)-1 {
			log.Println()
			log.Println("   ─────────────────────────")
			log.Println()
		}
	}
}
