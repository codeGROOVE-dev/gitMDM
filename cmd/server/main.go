// Package main implements the gitMDM server that receives and stores compliance reports.
package main

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/codeGROOVE-dev/retry"
	"gitmdm/internal/gitstore"
	"gitmdm/internal/types"
)

const (
	// HTTP timeouts.
	readTimeout  = 15 * time.Second
	writeTimeout = 15 * time.Second
	idleTimeout  = 60 * time.Second

	// Request validation limits.
	maxFieldLength  = 255
	maxCheckName    = 100
	maxCheckOutput  = 10240       // 10KB per check
	maxRequestBody  = 1024 * 1024 // 1MB limit
	shutdownTimeout = 10 * time.Second

	// Retry configuration for git operations.
	maxRetries     = 3
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second

	// Failed reports queue size.
	failedReportsQueueSize = 1000
)

//go:embed templates/*
var templates embed.FS

var (
	gitURL = flag.String("git", "", "Git repository URL or path to clone to temp directory")
	clone  = flag.String("clone", "", "Path to existing local git clone to work in directly")
	port   = flag.String("port", "8080", "Server port")
	apiKey = flag.String("api-key", "", "API key for authentication (optional but recommended)")
)

type Server struct {
	store         *gitstore.Store
	tmpl          *template.Template
	devices       map[string]*types.Device
	failedReports chan *types.Device
	mu            sync.RWMutex
	healthMu      sync.RWMutex
	statsmu       sync.RWMutex
	requestCount  int64
	errorCount    int64
	healthy       bool
}

func main() {
	flag.Parse()

	if *gitURL == "" && *clone == "" {
		log.Fatal("Either -git (repository to clone) or -clone (existing local clone) is required")
	}
	if *gitURL != "" && *clone != "" {
		log.Fatal("Cannot specify both -git and -clone")
	}

	ctx, cancel := context.WithCancel(context.Background())

	var store *gitstore.Store
	var err error

	if *clone != "" {
		// Use existing local clone directly (no push/pull)
		store, err = gitstore.NewLocal(ctx, *clone)
	} else {
		// Clone repository to temp directory (with push/pull)
		store, err = gitstore.NewRemote(ctx, *gitURL)
	}

	if err != nil {
		cancel() // Cancel context before fatal exit
		log.Fatalf("[ERROR] Failed to initialize git store: %v", err)
	}
	defer cancel()

	// Create template with helper functions
	funcMap := template.FuncMap{
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "N/A"
			}
			return t.Format("2006-01-02 15:04:05")
		},
		"formatAgo": func(t time.Time) string {
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
		},
	}

	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(templates, "templates/*.html"))

	server := &Server{
		store:         store,
		devices:       make(map[string]*types.Device),
		tmpl:          tmpl,
		failedReports: make(chan *types.Device, failedReportsQueueSize),
		healthy:       true,
	}

	if err := server.loadDevices(ctx); err != nil {
		log.Printf("[WARN] Failed to load existing devices: %v", err)
	}

	// Start failed reports processor
	go server.processFailedReports(ctx)

	// Log security configuration
	if *apiKey != "" {
		log.Println("[INFO] API key authentication enabled")
	} else {
		log.Println("[WARN] Running without API key authentication")
	}

	log.Printf("[INFO] Retry configuration: max_retries=%d, initial_backoff=%v, max_backoff=%v",
		maxRetries, initialBackoff, maxBackoff)
	log.Printf("[INFO] Failed reports queue size: %d", failedReportsQueueSize)

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleIndex)
	mux.HandleFunc("/device/", server.handleDevice)
	mux.HandleFunc("/api/v1/report", server.handleReport)
	mux.HandleFunc("/api/v1/devices", server.handleAPIDevices)
	mux.HandleFunc("/health", server.handleHealth)

	srv := &http.Server{
		Addr:           ":" + *port,
		Handler:        loggingMiddleware(mux),
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		IdleTimeout:    idleTimeout,
		MaxHeaderBytes: 1 << 16, // 64KB max header size
	}

	go func() {
		log.Printf("[INFO] Server starting on port %s", *port)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("[ERROR] Server failed: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("[INFO] Shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, shutdownTimeout)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[ERROR] Server shutdown error: %v", err)
	} else {
		log.Println("[INFO] Server shutdown complete")
	}
}

func (s *Server) loadDevices(ctx context.Context) error {
	start := time.Now()
	devices, err := s.store.ListDevices(ctx)
	if err != nil {
		return fmt.Errorf("failed to list devices: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, device := range devices {
		s.devices[device.HardwareID] = device
	}

	log.Printf("[INFO] Loaded %d devices from git repository in %v", len(devices), time.Since(start))
	return nil
}

func (s *Server) processFailedReports(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Process all queued reports
			for {
				select {
				case device := <-s.failedReports:
					log.Printf("[INFO] Retrying failed report for device %s", device.HardwareID)
					err := retry.Do(func() error {
						return s.store.SaveDevice(ctx, device)
					}, retry.Attempts(maxRetries), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff))

					if err != nil {
						log.Printf("[ERROR] Failed to retry saving device %s: %v", device.HardwareID, err)
						// Re-queue if there's space, otherwise drop
						select {
						case s.failedReports <- device:
						default:
							log.Printf("[WARN] Dropping failed device report - queue full")
						}
					} else {
						log.Printf("[INFO] Successfully saved queued device %s", device.HardwareID)
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

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.incrementRequestCount()

	if r.URL.Path != "/" {
		s.incrementErrorCount()
		http.NotFound(w, r)
		return
	}

	s.mu.RLock()
	devices := make([]*types.Device, 0, len(s.devices))
	for _, d := range s.devices {
		devices = append(devices, d)
	}
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "index.html", devices); err != nil {
		s.incrementErrorCount()
		log.Printf("[ERROR] Template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	s.incrementRequestCount()

	// Security: Only allow GET requests for device viewing
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hardwareID := strings.TrimPrefix(r.URL.Path, "/device/")
	if hardwareID == "" {
		s.incrementErrorCount()
		http.NotFound(w, r)
		return
	}

	s.mu.RLock()
	device, exists := s.devices[hardwareID]
	s.mu.RUnlock()

	if !exists {
		s.incrementErrorCount()
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "device.html", device); err != nil {
		s.incrementErrorCount()
		log.Printf("[ERROR] Template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
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

	// Security: Check API key if configured
	if *apiKey != "" {
		providedKey := request.Header.Get("X-API-Key")
		// Security: Don't accept API key from query params (exposes in logs)
		if !constantTimeCompare(providedKey, *apiKey) {
			s.incrementErrorCount()
			log.Printf("[WARN] Unauthorized request from %s", request.RemoteAddr)
			http.Error(writer, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	ctx := request.Context()
	var report types.DeviceReport
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
	if !isValidHardwareID(report.HardwareID) {
		s.incrementErrorCount()
		log.Printf("[WARN] Invalid Hardware ID format from %s", request.RemoteAddr)
		http.Error(writer, "Invalid Hardware ID format", http.StatusBadRequest)
		return
	}
	if len(report.Hostname) > maxFieldLength {
		s.incrementErrorCount()
		log.Printf("[WARN] Hostname too long from %s: %d bytes", request.RemoteAddr, len(report.Hostname))
		http.Error(writer, "Hostname too long", http.StatusBadRequest)
		return
	}
	if len(report.User) > maxFieldLength {
		s.incrementErrorCount()
		log.Printf("[WARN] Username too long from %s: %d bytes", request.RemoteAddr, len(report.User))
		http.Error(writer, "Username too long", http.StatusBadRequest)
		return
	}

	// Security: Validate checks
	for name, check := range report.Checks {
		if len(name) > maxCheckName {
			s.incrementErrorCount()
			log.Printf("[WARN] Check name too long from %s: %d bytes", request.RemoteAddr, len(name))
			http.Error(writer, "Check name too long", http.StatusBadRequest)
			return
		}
		// Additional validation: only allow safe characters in check names
		if !isValidCheckName(name) {
			s.incrementErrorCount()
			log.Printf("[WARN] Invalid check name format from %s", request.RemoteAddr)
			http.Error(writer, "Invalid check name format", http.StatusBadRequest)
			return
		}
		// Check combined output size (stdout + stderr)
		totalOutput := len(check.Stdout) + len(check.Stderr)
		if totalOutput > maxCheckOutput {
			s.incrementErrorCount()
			log.Printf("[WARN] Check output too large from %s: %s (stdout: %d, stderr: %d, total: %d bytes)",
				request.RemoteAddr, name, len(check.Stdout), len(check.Stderr), totalOutput)
			http.Error(writer, "Check output too large", http.StatusBadRequest)
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
	device := &types.Device{
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
	s.mu.Unlock()

	log.Printf("[INFO] Received report from %s (device: %s, checks: %d) in %v",
		request.RemoteAddr, device.HardwareID, len(device.Checks), time.Since(start))

	// Attempt to save to git store with graceful degradation
	err := retry.Do(func() error {
		return s.store.SaveDevice(ctx, device)
	}, retry.Attempts(maxRetries), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff))
	if err != nil {
		log.Printf("[WARN] Failed to save device %s to git store after %d retries: %v", device.HardwareID, maxRetries, err)
		// Queue for later retry if queue not full
		select {
		case s.failedReports <- device:
			log.Printf("[INFO] Device %s queued for retry processing", device.HardwareID)
		default:
			log.Printf("[WARN] Failed reports queue is full, device %s will not be retried", device.HardwareID)
			s.setHealthy(false)
		}
		// Continue processing - don't fail the request due to storage issues
	}

	// Always respond successfully since we have the data in memory
	writer.WriteHeader(http.StatusOK)
	writer.Header().Set("Content-Type", "application/json")
	if _, err := writer.Write([]byte(`{"status":"ok"}`)); err != nil {
		log.Printf("[WARN] Error writing response: %v", err)
	}
}

func (s *Server) handleAPIDevices(w http.ResponseWriter, r *http.Request) {
	s.incrementRequestCount()

	if r.Method != http.MethodGet {
		s.incrementErrorCount()
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	devices := make([]*types.Device, 0, len(s.devices))
	for _, d := range s.devices {
		devices = append(devices, d)
	}
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(devices); err != nil {
		s.incrementErrorCount()
		log.Printf("[ERROR] Failed to encode devices: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleHealth(writer http.ResponseWriter, _ *http.Request) {
	s.incrementRequestCount()

	s.healthMu.RLock()
	healthy := s.healthy
	s.healthMu.RUnlock()

	s.statsmu.RLock()
	requestCount := s.requestCount
	errorCount := s.errorCount
	s.statsmu.RUnlock()

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

	writer.WriteHeader(statusCode)
	writer.Header().Set("Content-Type", "application/json")
	if _, err := writer.Write([]byte(response)); err != nil {
		log.Printf("[WARN] Error writing health response: %v", err)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security: Add comprehensive security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")

		start := time.Now()
		next.ServeHTTP(w, r)
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
	s.statsmu.Lock()
	s.requestCount++
	s.statsmu.Unlock()
}

func (s *Server) incrementErrorCount() {
	s.statsmu.Lock()
	s.errorCount++
	s.statsmu.Unlock()
}

func (s *Server) setHealthy(healthy bool) {
	s.healthMu.Lock()
	s.healthy = healthy
	s.healthMu.Unlock()

	if !healthy {
		log.Printf("[WARN] Server health status changed to degraded")
	} else {
		log.Printf("[INFO] Server health status changed to healthy")
	}
}

// constantTimeCompare performs constant-time string comparison to prevent timing attacks.
func constantTimeCompare(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// isValidHardwareID validates that a hardware ID contains only safe characters.
func isValidHardwareID(id string) bool {
	// Allow alphanumeric, hyphens, underscores, and dots (common in UUIDs and machine IDs)
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return len(id) > 0
}

// isValidCheckName validates that a check name contains only safe characters.
func isValidCheckName(name string) bool {
	// Allow alphanumeric, hyphens, and underscores only
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_') {
			return false
		}
	}
	return len(name) > 0
}
