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
	"gitmdm/internal/gitmdm"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/codeGROOVE-dev/retry"

	"gopkg.in/yaml.v3"
)

const (
	// Command execution timeout.
	commandTimeout = 10 * time.Second
	// Maximum output size to prevent memory exhaustion.
	maxOutputSize = 10 * 1024 // 10KB limit
	// Maximum log output length for readability.
	maxLogLength = 200
	// Minimum parts required for IOPlatformUUID parsing.
	minUUIDParts = 4
	// Retry configuration.
	maxRetries     = 3
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second
	// HTTP client timeout.
	httpTimeout = 30 * time.Second
	// Queue size for failed reports.
	failedReportsQueueSize = 100
)

//go:embed checks.yaml
var checksConfig []byte

var (
	server   = flag.String("server", "", "Server URL (e.g., http://localhost:8080)")
	runCheck = flag.String("run", "", "Run a single check and exit")
	interval = flag.Duration("interval", 5*time.Minute, "Polling interval")
	debug    = flag.Bool("debug", false, "Enable debug logging")
)

// ChecksConfig holds the configuration for compliance checks.
type ChecksConfig struct {
	Checks map[string]map[string]string `yaml:"checks"`
}

// Agent represents the gitMDM agent that collects compliance data.
type Agent struct {
	config        *ChecksConfig
	httpClient    *http.Client
	failedReports chan gitmdm.DeviceReport
	serverURL     string
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

	if *runCheck != "" {
		// Security: Validate check name to prevent injection
		if !isValidCheckName(*runCheck) {
			log.Fatal("Invalid check name - only alphanumeric and underscore allowed")
		}
		output := agent.runSingleCheck(*runCheck)
		log.Print(output)
		if !strings.HasSuffix(output, "\n") {
			log.Print("\n")
		}
		return
	}

	if *server == "" {
		log.Fatal("Server URL is required (use -server flag)")
	}

	agent.serverURL = strings.TrimSuffix(*server, "/")

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
	}, retry.Attempts(maxRetries), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff))
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
		return fmt.Errorf("server returned status %d", resp.StatusCode)
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
			a.processQueuedReports(ctx)
		}
	}
}

func (a *Agent) processQueuedReports(ctx context.Context) {
	for {
		select {
		case report := <-a.failedReports:
			a.retryFailedReport(ctx, report)
		default:
			// No more reports to process
			return
		}
	}
}

func (a *Agent) retryFailedReport(ctx context.Context, report gitmdm.DeviceReport) {
	log.Printf("[INFO] Retrying failed report for device %s", report.HardwareID)
	err := retry.Do(func() error {
		return a.sendReport(ctx, report)
	}, retry.Attempts(maxRetries), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff))

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

	for checkName, checkCommands := range a.config.Checks {
		checkStart := time.Now()
		var command string

		// First check exact OS match
		if cmd, exists := checkCommands[osName]; exists {
			command = cmd
		} else {
			// Check for comma-separated OS lists
			found := false
			for osListKey, cmd := range checkCommands {
				osList := strings.Split(osListKey, ",")
				for _, osItem := range osList {
					if strings.TrimSpace(osItem) == osName {
						command = cmd
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
				cmd, exists := checkCommands["all"]
				if !exists {
					if *debug {
						log.Printf("[DEBUG] Check %s not available for OS %s", checkName, osName)
					}
					continue
				}
				command = cmd
			}
		}

		check := a.executeCommandWithPipes(ctx, checkName, command)
		checks[checkName] = check

		// Determine if check succeeded based on exit code
		if check.ExitCode != 0 {
			failureCount++
			if *debug {
				log.Printf("[DEBUG] Check %s failed (exit %d) in %v: %s", checkName, check.ExitCode, time.Since(checkStart), command)
			}
		} else {
			successCount++
			if *debug {
				log.Printf("[DEBUG] Check %s completed successfully in %v: %s", checkName, time.Since(checkStart), command)
			}
		}
	}

	log.Printf("[INFO] Completed %d checks (%d successful, %d failed) in %v",
		successCount+failureCount, successCount, failureCount, time.Since(start))

	return checks
}

func (a *Agent) runSingleCheck(checkName string) string {
	osName := runtime.GOOS

	checkCommands, exists := a.config.Checks[checkName]
	if !exists {
		return fmt.Sprintf("Check '%s' not found", checkName)
	}

	var command string
	// First check exact OS match
	if cmd, exists := checkCommands[osName]; exists {
		command = cmd
	} else {
		// Check for comma-separated OS lists
		found := false
		for osListKey, cmd := range checkCommands {
			osList := strings.Split(osListKey, ",")
			for _, osItem := range osList {
				if strings.TrimSpace(osItem) == osName {
					command = cmd
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
			cmd, exists := checkCommands["all"]
			if !exists {
				return fmt.Sprintf("Check '%s' not available for %s", checkName, osName)
			}
			command = cmd
		}
	}

	check := a.executeCommandWithPipes(context.Background(), "", command)
	// For single check output, combine stdout and stderr for display
	output := check.Stdout
	if check.Stderr != "" {
		output += "\n--- STDERR ---\n" + check.Stderr
	}
	if check.ExitCode != 0 {
		output += fmt.Sprintf("\n--- EXIT CODE: %d ---", check.ExitCode)
	}
	return output
}

func isValidCheckName(name string) bool {
	// Security: Only allow alphanumeric, underscore, and hyphen
	const maxCheckNameLength = 100
	for _, r := range name {
		if (r < 'a' || r > 'z') &&
			(r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') &&
			r != '_' && r != '-' {
			return false
		}
	}
	return name != "" && len(name) <= maxCheckNameLength
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
