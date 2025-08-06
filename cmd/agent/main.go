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
	"gitmdm/internal/types"
	"gopkg.in/yaml.v3"
)

const (
	// Command execution timeout.
	commandTimeout = 10 * time.Second
	// Maximum output size to prevent memory exhaustion.
	maxOutputSize = 10 * 1024 // 10KB limit
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

type ChecksConfig struct {
	Checks map[string]map[string]string `yaml:"checks"`
}

type Agent struct {
	config        *ChecksConfig
	httpClient    *http.Client
	serverURL     string
	hardwareID    string
	hostname      string
	user          string
	failedReports chan types.DeviceReport
}

func main() {
	flag.Parse()

	var config ChecksConfig
	if err := yaml.Unmarshal(checksConfig, &config); err != nil {
		log.Fatalf("Failed to parse checks config: %v", err)
	}

	agent := &Agent{
		config:     &config,
		hardwareID: hardwareID(),
		hostname:   hostname(),
		user:       currentUser(),
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
		failedReports: make(chan types.DeviceReport, failedReportsQueueSize),
	}

	if *runCheck != "" {
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
	report := types.DeviceReport{
		HardwareID: a.hardwareID,
		Hostname:   a.hostname,
		User:       a.user,
		Timestamp:  time.Now(),
		Checks:     a.runAllChecks(ctx),
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
			log.Printf("[INFO] Report queued for retry processing")
		default:
			log.Printf("[WARN] Failed reports queue is full, dropping report")
		}
		return
	}

	if *debug {
		log.Printf("[DEBUG] Successfully reported to server in %v", time.Since(start))
	}
}

func (a *Agent) sendReport(ctx context.Context, report types.DeviceReport) error {
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
			// Process all queued reports
			for {
				select {
				case report := <-a.failedReports:
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
							log.Printf("[WARN] Dropping failed report - queue full")
						}
					} else {
						log.Printf("[INFO] Successfully sent queued report")
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

func (a *Agent) runAllChecks(ctx context.Context) map[string]types.Check {
	start := time.Now()
	checks := make(map[string]types.Check)
	osName := runtime.GOOS
	successCount := 0
	failureCount := 0

	if *debug {
		log.Printf("[DEBUG] Running %d checks for OS: %s", len(a.config.Checks), osName)
	}

	for checkName, checkCommands := range a.config.Checks {
		checkStart := time.Now()
		var command string

		if cmd, exists := checkCommands[osName]; exists {
			command = cmd
		} else if cmd, exists := checkCommands["all"]; exists {
			command = cmd
		} else {
			if *debug {
				log.Printf("[DEBUG] Check %s not available for OS %s", checkName, osName)
			}
			continue
		}

		check := a.executeCommandWithName(ctx, checkName, command)
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
	if cmd, exists := checkCommands[osName]; exists {
		command = cmd
	} else if cmd, exists := checkCommands["all"]; exists {
		command = cmd
	} else {
		return fmt.Sprintf("Check '%s' not available for %s", checkName, osName)
	}

	check := a.executeCommand(context.Background(), command)
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

func (a *Agent) executeCommand(ctx context.Context, command string) types.Check {
	// Use the new implementation that captures stdout/stderr separately
	return a.executeCommandWithPipes(ctx, "", command)
}

func (a *Agent) executeCommandWithName(ctx context.Context, checkName, command string) types.Check {
	// Use the new implementation that captures stdout/stderr separately
	return a.executeCommandWithPipes(ctx, checkName, command)
}

func hardwareID() string {
	var id string
	start := time.Now()

	if *debug {
		log.Printf("[DEBUG] Detecting hardware ID for OS: %s", runtime.GOOS)
	}

	switch runtime.GOOS {
	case "darwin":
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "IOPlatformUUID") {
					parts := strings.Split(line, "\"")
					if len(parts) >= minUUIDParts {
						id = parts[3]
						if *debug {
							log.Printf("[DEBUG] Found macOS hardware UUID: %s", id)
						}
						break
					}
				}
			}
		} else if *debug {
			log.Printf("[DEBUG] Failed to get macOS hardware ID via ioreg: %v", err)
		}
	case "linux":
		if data, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
			id = strings.TrimSpace(string(data))
			if *debug {
				log.Printf("[DEBUG] Found Linux hardware UUID from DMI: %s", id)
			}
		} else if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			id = strings.TrimSpace(string(data))
			if *debug {
				log.Printf("[DEBUG] Found Linux machine ID: %s", id)
			}
		} else if *debug {
			log.Printf("[DEBUG] Failed to get Linux hardware ID from both DMI and machine-id")
		}
	case "freebsd", "openbsd":
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sysctl", "-n", "kern.hostuuid")
		if output, err := cmd.Output(); err == nil {
			id = strings.TrimSpace(string(output))
			if *debug {
				log.Printf("[DEBUG] Found BSD hardware UUID: %s", id)
			}
		} else if *debug {
			log.Printf("[DEBUG] Failed to get BSD hardware ID via sysctl: %v", err)
		}
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

func hostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func currentUser() string {
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	if user := os.Getenv("USERNAME"); user != "" {
		return user
	}
	return "unknown"
}
