// Package main implements the gitMDM server that receives and stores compliance reports.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"gitmdm/internal/gitmdm"
	"gitmdm/internal/gitstore"
	"gitmdm/internal/viewmodels"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/codeGROOVE-dev/retry"
)

const (
	// HTTP timeouts.
	readTimeout  = 15 * time.Second
	writeTimeout = 15 * time.Second
	idleTimeout  = 60 * time.Second

	// Request validation limits.
	maxFieldLength  = 255
	maxCheckName    = 100
	maxCheckOutput  = 92160       // 90KB per check
	maxRequestBody  = 1024 * 1024 // 1MB limit
	maxHeaderBytes  = 1 << 16     // 64KB max header size
	shutdownTimeout = 10 * time.Second

	// Retry configuration for git operations.
	maxRetries     = 3
	initialBackoff = 1 * time.Second
	maxBackoff     = 2 * time.Minute // Wait up to 2 minutes with exponential backoff

	// Failed reports queue size.
	failedReportsQueueSize = 1000

	// Hardware ID constants.
	minHardwareIDLength = 10

	// Compliance score thresholds.
	excellentThreshold = 0.9
	goodThreshold      = 0.7
	fairThreshold      = 0.5
)

//go:embed templates/*
var templates embed.FS

//go:embed static/*
var staticFiles embed.FS

var (
	gitURL = flag.String("git", os.Getenv("GIT_REPO"), "Git repository URL or path to clone to temp directory (env: GIT_REPO)")
	clone  = flag.String("clone", "", "Path to existing local git clone to work in directly")
	port   = flag.String("port", func() string {
		if p := os.Getenv("PORT"); p != "" {
			return p
		}
		return "8080"
	}(), "Server port (env: PORT)")
	joinKey = flag.String("join-key", os.Getenv("JOIN_KEY"), "Join key for agent registration (env: JOIN_KEY)")
)

// ComplianceCache stores pre-calculated compliance stats for a device.
type ComplianceCache struct {
	PassCount int
	FailCount int
	NACount   int
}

// Server represents the gitMDM server that receives and stores compliance reports.
type Server struct {
	store           *gitstore.Store
	tmpl            *template.Template
	devices         map[string]*gitmdm.Device
	complianceCache map[string]*ComplianceCache // Cache compliance stats per device
	failedReports   chan *gitmdm.Device
	mu              sync.RWMutex
	healthMu        sync.RWMutex
	statsMu         sync.RWMutex
	requestCount    int64
	errorCount      int64
	healthy         bool
}

// generateJoinKeyFromHardwareID generates a join key from the server's hardware ID.
func generateJoinKeyFromHardwareID() string {
	// Get hardware ID similar to agent
	var id string
	switch runtime.GOOS {
	case "darwin":
		// macOS: Use hardware UUID
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "system_profiler", "SPHardwareDataType")
		if output, err := cmd.Output(); err == nil {
			outputStr := string(output)
			if idx := strings.Index(outputStr, "Hardware UUID:"); idx != -1 {
				line := outputStr[idx:]
				if endIdx := strings.Index(line, "\n"); endIdx != -1 {
					line = line[:endIdx]
				}
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					id = parts[2]
				}
			}
		}
	case "linux":
		// Linux: Try machine-id first
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			id = strings.TrimSpace(string(data))
		} else if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
			id = strings.TrimSpace(string(data))
		}
	case "windows":
		// Windows: Use wmic to get UUID
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "wmic", "csproduct", "get", "uuid", "/value")
		if output, err := cmd.Output(); err == nil {
			outputStr := string(output)
			if idx := strings.Index(outputStr, "UUID="); idx != -1 {
				id = strings.TrimSpace(strings.TrimPrefix(outputStr[idx:], "UUID="))
			}
		}
	default:
		// Other operating systems: fallback will be used
	}

	// Fallback to hostname-based ID
	if id == "" {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}
		hash := sha256.Sum256([]byte(hostname + runtime.GOOS))
		id = hex.EncodeToString(hash[:16])
	}

	// Take last 10 alphanumeric characters for the join key
	// Remove any non-alphanumeric characters first
	cleanID := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, id)

	// Take last 10 characters (or full string if shorter)
	if len(cleanID) > minHardwareIDLength {
		return strings.ToUpper(cleanID[len(cleanID)-10:])
	}
	return strings.ToUpper(cleanID)
}

func main() {
	flag.Parse()

	// Validate flags
	if *gitURL == "" && *clone == "" {
		log.Fatal("Either -git (repository to clone) or -clone (existing local clone) is required")
	}
	if *gitURL != "" && *clone != "" {
		log.Fatal("Cannot specify both -git and -clone")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize git store
	var store *gitstore.Store
	var err error
	if *clone != "" {
		store, err = gitstore.NewLocal(ctx, *clone)
	} else {
		store, err = gitstore.NewRemote(ctx, *gitURL)
	}
	if err != nil {
		log.Printf("[ERROR] Failed to initialize git store: %v", err)
		cancel()
		return
	}

	// Create server
	funcMap := template.FuncMap{
		"formatTime":    formatTimeFunc,
		"formatAgo":     formatAgoFunc,
		"inc":           func(i int) int { return i + 1 },
		"truncateLines": truncateLinesFunc,
		"safeID": func(name string) string {
			return strings.ReplaceAll(strings.ReplaceAll(name, "_", "-"), ".", "-")
		},
		"sub":  func(a, b int) int { return a - b },
		"add":  func(a, b int) int { return a + b },
		"mul":  func(a, b int) int { return a * b },
		"mulf": func(a, b float64) float64 { return a * b },
		"div": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"title": func(s string) string {
			// Convert snake_case to Title Case
			words := strings.Split(strings.ReplaceAll(s, "_", " "), " ")
			for i, word := range words {
				if word != "" {
					words[i] = strings.ToUpper(word[:1]) + word[1:]
				}
			}
			return strings.Join(words, " ")
		},
		"contains": strings.Contains,
	}
	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(templates, "templates/*.html"))

	server := &Server{
		store:           store,
		devices:         make(map[string]*gitmdm.Device),
		complianceCache: make(map[string]*ComplianceCache),
		tmpl:            tmpl,
		failedReports:   make(chan *gitmdm.Device, failedReportsQueueSize),
		healthy:         true,
	}

	// Load existing devices
	if err := server.loadDevices(ctx); err != nil {
		log.Printf("[WARN] Failed to load existing devices: %v", err)
	}

	// Start background processors
	go server.processFailedReports(ctx)

	// Generate join key from hardware ID if not set
	if *joinKey == "" {
		*joinKey = generateJoinKeyFromHardwareID()
		log.Printf("[INFO] Generated join key from hardware ID: %s", *joinKey)
	}

	// Log configuration
	log.Println("[INFO] ═══════════════════════════════════════════════════════════════")
	log.Print("[INFO] GitMDM Server Started")
	log.Printf("[INFO] Join Key: %s", *joinKey)
	log.Print("[INFO] ")
	log.Print("[INFO] To register an agent, run:")
	log.Printf("[INFO]   ./gitmdm-agent --server http://localhost:%s --join %s", *port, *joinKey)
	log.Println("[INFO] ═══════════════════════════════════════════════════════════════")
	log.Printf("[INFO] Retry configuration: max_retries=%d, initial_backoff=%v, max_backoff=%v",
		maxRetries, initialBackoff, maxBackoff)
	log.Printf("[INFO] Failed reports queue size: %d", failedReportsQueueSize)

	// Create and start HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleIndex)
	mux.HandleFunc("/device/", server.handleDevice)
	mux.HandleFunc("/api/v1/report", server.handleReport)
	mux.HandleFunc("/api/v1/devices", server.handleAPIDevices)
	mux.HandleFunc("/health", server.handleHealth)

	// Serve static files
	// Use Sub to get the static directory from the embedded filesystem
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		cancel()
		log.Fatalf("[ERROR] Failed to get static filesystem: %v", err) //nolint:gocritic // exitAfterDefer
	}
	staticHandler := http.FileServer(http.FS(staticFS))
	mux.Handle("/static/", http.StripPrefix("/static/", staticHandler))

	srv := &http.Server{
		Addr:           ":" + *port,
		Handler:        loggingMiddleware(mux),
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		IdleTimeout:    idleTimeout,
		MaxHeaderBytes: maxHeaderBytes,
	}

	go func() {
		log.Printf("[INFO] Server starting on port %s", *port)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("[ERROR] Server failed: %v", err)
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	// Graceful shutdown
	log.Println("[INFO] Shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, shutdownTimeout)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[ERROR] Server shutdown error: %v", err)
	} else {
		log.Println("[INFO] Server shutdown complete")
	}
}

// Template function implementations.

func formatTimeFunc(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	return t.Format("2006-01-02 15:04:05")
}

func formatAgoFunc(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	dur := time.Since(t).Round(time.Second)
	if dur < time.Minute {
		return fmt.Sprintf("%d seconds ago", int(dur.Seconds()))
	}
	if dur < time.Hour {
		return fmt.Sprintf("%d minutes ago", int(dur.Minutes()))
	}
	if dur < 24*time.Hour {
		return fmt.Sprintf("%d hours ago", int(dur.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(dur.Hours()/24))
}

func truncateLinesFunc(text string, maxLines any) string {
	if text == "" {
		return text
	}

	var maxLinesInt int
	switch v := maxLines.(type) {
	case int:
		maxLinesInt = v
	case float64:
		maxLinesInt = int(v)
	default:
		maxLinesInt = 100 // default fallback
	}

	lines := strings.Split(text, "\n")
	if len(lines) <= maxLinesInt {
		return text
	}
	truncated := strings.Join(lines[:maxLinesInt], "\n")
	return truncated + "\n... (output truncated, showing first " + strconv.Itoa(maxLinesInt) + " lines)"
}

func (s *Server) loadDevices(ctx context.Context) error {
	start := time.Now()
	devices, err := s.store.LoadDevices(ctx)
	if err != nil {
		return fmt.Errorf("failed to list devices: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, device := range devices {
		s.devices[device.HardwareID] = device
		// Calculate and cache compliance stats
		s.updateComplianceCacheLocked(device)
	}

	log.Printf("[INFO] Loaded %d devices from git repository in %v", len(devices), time.Since(start))
	return nil
}

// updateComplianceCacheLocked updates the compliance cache for a device.
// Caller must hold s.mu lock.
func (s *Server) updateComplianceCacheLocked(device *gitmdm.Device) {
	cache := &ComplianceCache{}

	// Filter out checks that are more than 1 hour older than LastSeen
	staleThreshold := device.LastSeen.Add(-1 * time.Hour)

	for _, check := range device.Checks {
		// Skip stale checks that are too old
		if !check.Timestamp.IsZero() && check.Timestamp.Before(staleThreshold) {
			continue
		}

		switch check.Status {
		case "pass":
			cache.PassCount++
		case "fail":
			cache.FailCount++
		default: // "n/a" or empty
			cache.NACount++
		}
	}

	s.complianceCache[device.HardwareID] = cache
}

func (s *Server) processFailedReports(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Process all queued devices
			for {
				select {
				case device := <-s.failedReports:
					s.retryFailedDevice(ctx, device)
				default:
					// No more reports to process
					goto nextTick
				}
			}
		nextTick:
		}
	}
}

func (s *Server) retryFailedDevice(ctx context.Context, device *gitmdm.Device) {
	log.Printf("[INFO] Retrying failed report for device %s", device.HardwareID)
	err := retry.Do(func() error {
		return s.store.SaveDevice(ctx, device)
	},
		retry.Attempts(maxRetries),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.Delay(initialBackoff),
		retry.MaxDelay(maxBackoff))

	if err != nil {
		log.Printf("[ERROR] Failed to retry saving device %s: %v", device.HardwareID, err)
		// Re-queue if there's space, otherwise drop
		select {
		case s.failedReports <- device:
		default:
			log.Print("[WARN] Dropping failed device report - queue full")
		}
	} else {
		log.Printf("[INFO] Successfully saved queued device %s", device.HardwareID)
	}
}

func (s *Server) handleIndex(writer http.ResponseWriter, req *http.Request) {
	s.incrementRequestCount()

	if req.URL.Path != "/" {
		s.incrementErrorCount()
		http.NotFound(writer, req)
		return
	}

	// Get filter parameters
	search := strings.ToLower(strings.TrimSpace(req.URL.Query().Get("search")))
	status := req.URL.Query().Get("status")

	// Get pagination parameters
	page := 1
	if pageStr := req.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	const itemsPerPage = 50

	s.mu.RLock()
	// Build view models using cached compliance data
	allDevices := make([]viewmodels.DeviceListItem, 0, len(s.devices))

	for _, device := range s.devices {
		// Extract OS and version information
		osName, osVersion := viewmodels.ExtractOSInfo(device)

		item := viewmodels.DeviceListItem{
			HardwareID: device.HardwareID,
			Hostname:   device.Hostname,
			User:       device.User,
			OS:         osName,
			Version:    osVersion,
			LastSeen:   device.LastSeen,
		}

		// Use cached compliance stats
		if cache, exists := s.complianceCache[device.HardwareID]; exists {
			item.PassCount = cache.PassCount
			item.FailCount = cache.FailCount
			item.NACount = cache.NACount

			// Calculate compliance score and emoji
			if item.PassCount+item.FailCount > 0 {
				item.ComplianceScore = float64(item.PassCount) / float64(item.PassCount+item.FailCount)

				switch {
				case item.ComplianceScore >= excellentThreshold:
					item.ComplianceEmoji = "🏆" // Excellent
					item.ComplianceClass = "excellent"
				case item.ComplianceScore >= goodThreshold:
					item.ComplianceEmoji = "👍" // Good
					item.ComplianceClass = "good"
				case item.ComplianceScore >= fairThreshold:
					item.ComplianceEmoji = "😐" // Meh
					item.ComplianceClass = "fair"
				default:
					item.ComplianceEmoji = "🔥" // This is fine
					item.ComplianceClass = "poor"
				}
			} else {
				item.ComplianceClass = "poor"
			}
		} else {
			item.ComplianceClass = "poor"
		}

		// Apply search filter
		if search != "" {
			if !strings.Contains(strings.ToLower(item.Hostname), search) &&
				!strings.Contains(strings.ToLower(item.User), search) {
				continue
			}
		}

		// Apply status filter
		if status != "" {
			switch status {
			case "excellent":
				if item.ComplianceClass != "excellent" {
					continue
				}
			case "good":
				if item.ComplianceClass != "good" {
					continue
				}
			case "issues":
				if item.ComplianceClass != "poor" && item.ComplianceClass != "fair" {
					continue
				}
			case "checking":
				if item.ComplianceScore > 0 {
					continue
				}
			default:
				// No filtering for unknown status
			}
		}

		allDevices = append(allDevices, item)
	}
	s.mu.RUnlock()

	// Apply pagination
	totalDevices := len(allDevices)
	totalPages := (totalDevices + itemsPerPage - 1) / itemsPerPage
	if totalPages == 0 {
		totalPages = 1
	}

	// Adjust page if out of bounds
	if page > totalPages {
		page = totalPages
	}

	// Calculate pagination slice
	start := (page - 1) * itemsPerPage
	end := start + itemsPerPage
	if end > totalDevices {
		end = totalDevices
	}

	var pagedDevices []viewmodels.DeviceListItem
	if start < totalDevices {
		pagedDevices = allDevices[start:end]
	} else {
		pagedDevices = []viewmodels.DeviceListItem{}
	}

	// Create view model with filter state
	viewModel := viewmodels.DeviceListView{
		Devices:     pagedDevices,
		Search:      req.URL.Query().Get("search"), // Keep original case for display
		Status:      status,
		Page:        page,
		TotalPages:  totalPages,
		Total:       totalDevices,
		HasPrevious: page > 1,
		HasNext:     page < totalPages,
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(writer, "index.html", viewModel); err != nil {
		s.incrementErrorCount()
		log.Printf("[ERROR] Template error: %v", err)
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleDevice(writer http.ResponseWriter, r *http.Request) {
	s.incrementRequestCount()

	// Security: Only allow GET requests for device viewing
	if r.Method != http.MethodGet {
		http.Error(writer, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hardwareID := strings.TrimPrefix(r.URL.Path, "/device/")
	if hardwareID == "" {
		s.incrementErrorCount()
		http.NotFound(writer, r)
		return
	}

	s.mu.RLock()
	device, exists := s.devices[hardwareID]
	s.mu.RUnlock()

	if !exists {
		s.incrementErrorCount()
		http.NotFound(writer, r)
		return
	}

	// Build detailed view model with compliance analysis
	viewData := viewmodels.BuildDeviceDetail(device)

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(writer, "device.html", viewData); err != nil {
		s.incrementErrorCount()
		log.Printf("[ERROR] Template error: %v", err)
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleReport(writer http.ResponseWriter, request *http.Request) {
	start := time.Now()
	s.incrementRequestCount()

	if request.Method != http.MethodPost {
		s.incrementErrorCount()
		http.Error(writer, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Security: Check join key - always required
	providedKey := request.Header.Get("X-Join-Key")
	// Security: Don't accept join key from query params (exposes in logs)
	// Use constant-time comparison to prevent timing attacks
	if len(providedKey) != len(*joinKey) || subtle.ConstantTimeCompare([]byte(providedKey), []byte(*joinKey)) != 1 {
		s.incrementErrorCount()
		log.Printf("[WARN] Unauthorized request from %s - invalid join key", request.RemoteAddr)
		http.Error(writer, "Unauthorized - invalid join key", http.StatusUnauthorized)
		return
	}

	ctx := request.Context()
	var report gitmdm.DeviceReport
	// Security: Limit request body size to prevent DoS
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBody)

	if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
		s.incrementErrorCount()
		log.Printf("[ERROR] Failed to decode report from %s: %v", request.RemoteAddr, err)
		http.Error(writer, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Security: Validate input fields
	if report.HardwareID == "" || len(report.HardwareID) > maxFieldLength {
		s.incrementErrorCount()
		log.Printf("[WARN] Invalid Hardware ID from %s: length %d", request.RemoteAddr, len(report.HardwareID))
		http.Error(writer, "Invalid Hardware ID", http.StatusBadRequest)
		return
	}
	// Additional validation: only allow safe characters in hardware ID
	// Allow alphanumeric, hyphens, underscores, and dots (common in UUIDs and machine IDs)
	isValid := true
	for _, r := range report.HardwareID {
		if (r < 'a' || r > 'z') &&
			(r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') &&
			r != '-' && r != '_' && r != '.' {
			isValid = false
			break
		}
	}
	if !isValid {
		s.incrementErrorCount()
		log.Printf("[WARN] Invalid Hardware ID format from %s", request.RemoteAddr)
		http.Error(writer, "Invalid Hardware ID format", http.StatusBadRequest)
		return
	}
	if len(report.Hostname) > maxFieldLength {
		s.incrementErrorCount()
		log.Printf("[WARN] Hostname too long from %s: %d bytes, limit: %d bytes", request.RemoteAddr, len(report.Hostname), maxFieldLength)
		errMsg := fmt.Sprintf("Hostname too long: %d bytes exceeds %d byte limit", len(report.Hostname), maxFieldLength)
		http.Error(writer, errMsg, http.StatusBadRequest)
		return
	}
	if len(report.User) > maxFieldLength {
		s.incrementErrorCount()
		log.Printf("[WARN] Username too long from %s: %d bytes, limit: %d bytes", request.RemoteAddr, len(report.User), maxFieldLength)
		http.Error(writer, "Username too long", http.StatusBadRequest)
		return
	}

	// Security: Validate checks
	for name, check := range report.Checks {
		if len(name) > maxCheckName {
			s.incrementErrorCount()
			log.Printf("[WARN] Check name too long from %s: %d bytes, limit: %d bytes", request.RemoteAddr, len(name), maxCheckName)
			http.Error(writer, "Check name too long", http.StatusBadRequest)
			return
		}
		// Additional validation: only allow safe characters in check names
		if !gitmdm.IsValidCheckName(name) {
			s.incrementErrorCount()
			log.Printf("[WARN] Invalid check name format from %s", request.RemoteAddr)
			http.Error(writer, "Invalid check name format", http.StatusBadRequest)
			return
		}
		// Check combined output size for all command outputs
		totalOutput := 0
		for _, output := range check.Outputs {
			totalOutput += len(output.Stdout) + len(output.Stderr)
		}
		if totalOutput > maxCheckOutput {
			s.incrementErrorCount()
			log.Printf("[WARN] Check output too large from %s: %s (%d commands, total: %d bytes, limit: %d bytes)",
				request.RemoteAddr, name, len(check.Outputs), totalOutput, maxCheckOutput)
			errMsg := fmt.Sprintf("Check output too large: %d bytes exceeds %d byte limit", totalOutput, maxCheckOutput)
			http.Error(writer, errMsg, http.StatusBadRequest)
			return
		}
	}

	// Extract client IP (handle X-Forwarded-For for proxies)
	clientIP := request.RemoteAddr
	if xff := request.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP from X-Forwarded-For
		if parts := strings.Split(xff, ","); len(parts) > 0 {
			clientIP = strings.TrimSpace(parts[0])
		}
	} else if xri := request.Header.Get("X-Real-IP"); xri != "" {
		clientIP = xri
	}

	now := time.Now()
	device := &gitmdm.Device{
		HardwareID: report.HardwareID,
		Hostname:   report.Hostname,
		User:       report.User,
		LastSeen:   now,
		LastIP:     clientIP,
		Checks:     report.Checks,
		// In-memory only fields
		SystemUptime:  report.SystemUptime,
		CPULoad:       report.CPULoad,
		LoggedInUsers: report.LoggedInUsers,
	}

	// Always update in-memory cache first for immediate availability
	s.mu.Lock()
	s.devices[device.HardwareID] = device
	// Update compliance cache
	s.updateComplianceCacheLocked(device)
	s.mu.Unlock()

	log.Printf("[INFO] Received report from %s (device: %s, checks: %d) in %v",
		request.RemoteAddr, device.HardwareID, len(device.Checks), time.Since(start))

	// Attempt to save to git store with graceful degradation
	retryCount := 0
	err := retry.Do(func() error {
		retryCount++
		if retryCount > 1 {
			log.Printf("[INFO] Retry attempt %d/%d for saving device %s to git", retryCount, maxRetries, device.HardwareID)
		}
		return s.store.SaveDevice(ctx, device)
	}, retry.Attempts(maxRetries), retry.DelayType(retry.FullJitterBackoffDelay), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff))
	if err != nil {
		log.Printf("[WARN] Failed to save device %s to git store after %d retries: %v", device.HardwareID, maxRetries, err)
		// Queue for later retry if queue not full
		select {
		case s.failedReports <- device:
			log.Printf("[INFO] Device %s queued for retry processing", device.HardwareID)
		default:
			log.Printf("[WARN] Failed reports queue is full, device %s will not be retried", device.HardwareID)
			// Set health status to degraded inline
			s.healthMu.Lock()
			if s.healthy {
				s.healthy = false
				log.Print("[WARN] Server health status changed to degraded")
			}
			s.healthMu.Unlock()
		}
		// Continue processing - don't fail the request due to storage issues
	}

	// Always respond successfully since we have the data in memory
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write([]byte(`{"status":"ok"}`)); err != nil {
		log.Printf("[WARN] Error writing response: %v", err)
	}
}

func (s *Server) handleAPIDevices(writer http.ResponseWriter, r *http.Request) {
	s.incrementRequestCount()

	if r.Method != http.MethodGet {
		s.incrementErrorCount()
		http.Error(writer, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	devices := make([]*gitmdm.Device, 0, len(s.devices))
	for _, d := range s.devices {
		devices = append(devices, d)
	}
	s.mu.RUnlock()

	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(devices); err != nil {
		s.incrementErrorCount()
		log.Printf("[ERROR] Failed to encode devices: %v", err)
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleHealth(writer http.ResponseWriter, _ *http.Request) {
	s.incrementRequestCount()

	s.healthMu.RLock()
	healthy := s.healthy
	s.healthMu.RUnlock()

	s.statsMu.RLock()
	requestCount := s.requestCount
	errorCount := s.errorCount
	s.statsMu.RUnlock()

	s.mu.RLock()
	deviceCount := len(s.devices)
	s.mu.RUnlock()

	status := "healthy"
	statusCode := http.StatusOK
	if !healthy {
		status = "degraded"
		statusCode = http.StatusServiceUnavailable
	}

	response := fmt.Sprintf(`{"status":%q,"devices":%d,"requests":%d,"errors":%d}`,
		status, deviceCount, requestCount, errorCount)

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)
	if _, err := writer.Write([]byte(response)); err != nil {
		log.Printf("[WARN] Error writing health response: %v", err)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, r *http.Request) {
		// Security: Add comprehensive security headers
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("X-XSS-Protection", "1; mode=block")
		writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Strict CSP - only allow self-hosted resources
		// Keep unsafe-inline for styles as templates use inline styles
		cspPolicy := "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; font-src 'self'"
		writer.Header().Set("Content-Security-Policy", cspPolicy)

		start := time.Now()
		next.ServeHTTP(writer, r)
		duration := time.Since(start)

		// Log with different levels based on duration and status
		if duration > 1*time.Second {
			log.Printf("[WARN] Slow request: %s %s %s %v", r.RemoteAddr, r.Method, r.URL.Path, duration)
		} else {
			log.Printf("[DEBUG] %s %s %s %v", r.RemoteAddr, r.Method, r.URL.Path, duration)
		}
	})
}

// Utility methods for tracking server statistics and health.
func (s *Server) incrementRequestCount() {
	s.statsMu.Lock()
	s.requestCount++
	s.statsMu.Unlock()
}

func (s *Server) incrementErrorCount() {
	s.statsMu.Lock()
	s.errorCount++
	s.statsMu.Unlock()
}
