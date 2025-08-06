// Package gitstore provides Git-based storage for device compliance data.
package gitstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/codeGROOVE-dev/retry"
	"gitmdm/internal/types"
)

const (
	// Directory permissions.
	deviceDirPerm = 0o750
	repoDirPerm   = 0o750
	// File permissions.
	infoFilePerm  = 0o600
	checkFilePerm = 0o600
	// String replacement constant.
	replacementChar = "-"
	// Retry configuration for git operations.
	maxRetries     = 3
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second
	// Git command timeout.
	gitTimeout = 30 * time.Second
)

// Store provides Git-based storage for device compliance data.
type Store struct {
	gitURL   string
	repoPath string
	mu       sync.Mutex
}

// isLocalRepo returns true if this is a local repository (not remote)
func (s *Store) isLocalRepo() bool {
	// If gitURL equals repoPath, it's a local repo (set during initialization)
	return s.gitURL == s.repoPath
}

// NewLocal creates a store using an existing local git clone.
// It will work directly in the repository and perform push/pull if a remote is configured.
func NewLocal(ctx context.Context, localPath string) (*Store, error) {
	absPath, err := filepath.Abs(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	// Check if it's a valid git repository
	if _, err := os.Stat(filepath.Join(absPath, ".git")); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("not a git repository: %s", absPath)
		}
		return nil, fmt.Errorf("failed to check git repository: %w", err)
	}

	s := &Store{
		repoPath: absPath,
	}

	// Check if remote is configured
	s.mu.Lock()
	output, err := s.runGitCommandOutput(ctx, "remote", "-v")
	s.mu.Unlock()
	
	if err == nil && strings.TrimSpace(output) != "" {
		// Has remote configured - enable push/pull
		s.gitURL = "remote"
		log.Printf("[INFO] Git store initialized with local clone: %s (remote configured, will push/pull)", absPath)
	} else {
		// No remote - work locally only
		s.gitURL = absPath
		log.Printf("[INFO] Git store initialized with local clone: %s (no remote, local only)", absPath)
	}

	// Create devices directory if it doesn't exist
	devicesDir := filepath.Join(s.repoPath, "devices")
	if err := os.MkdirAll(devicesDir, repoDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create devices directory: %w", err)
	}

	return s, nil
}

// NewRemote creates a store by cloning a repository to a temp directory.
// It will perform push/pull operations with the remote.
func NewRemote(ctx context.Context, gitURL string) (*Store, error) {
	tempDir := filepath.Join(os.TempDir(), fmt.Sprintf("gitmdm-%d", time.Now().Unix()))

	s := &Store{
		repoPath: tempDir,
		gitURL:   gitURL,
	}

	if err := s.initializeRemote(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize git store: %w", err)
	}

	log.Printf("[INFO] Git store initialized: %s (repo: %s)", gitURL, s.repoPath)
	return s, nil
}

// Deprecated: Use NewLocal or NewRemote instead
func New(ctx context.Context, gitURL string) (*Store, error) {
	// For backward compatibility, treat as remote
	return NewRemote(ctx, gitURL)
}

func (s *Store) initializeRemote(ctx context.Context) error {
	start := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Printf("[INFO] Cloning repository: %s to %s", s.gitURL, s.repoPath)
	
	if err := s.runGitCommandInDirWithRetry(ctx, "", "clone", s.gitURL, s.repoPath); err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}
	
	if err := s.runGitCommandWithRetry(ctx, "config", "user.email", "gitmdm@localhost"); err != nil {
		return err
	}
	if err := s.runGitCommandWithRetry(ctx, "config", "user.name", "gitMDM"); err != nil {
		return err
	}
	
	log.Printf("[INFO] Repository cloned successfully")

	devicesDir := filepath.Join(s.repoPath, "devices")
	if err := os.MkdirAll(devicesDir, repoDirPerm); err != nil {
		return fmt.Errorf("failed to create devices directory: %w", err)
	}

	log.Printf("[INFO] Git store initialization completed in %v", time.Since(start))
	return nil
}

// SaveDevice saves a device's compliance data to the Git repository.
func (s *Store) SaveDevice(ctx context.Context, device *types.Device) error {
	start := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	sanitizedID := sanitizeID(device.HardwareID)
	deviceDir := filepath.Join(s.repoPath, "devices", sanitizedID)

	log.Printf("[INFO] Processing device %s with %d checks", device.HardwareID, len(device.Checks))

	// Security: Verify the path stays within repo bounds
	absDeviceDir, err := filepath.Abs(deviceDir)
	if err != nil {
		return fmt.Errorf("failed to resolve device directory: %w", err)
	}
	absRepoPath, err := filepath.Abs(s.repoPath)
	if err != nil {
		return fmt.Errorf("failed to resolve repo path: %w", err)
	}
	if !strings.HasPrefix(absDeviceDir, absRepoPath) {
		return errors.New("security error: path traversal detected")
	}

	if err := os.MkdirAll(deviceDir, deviceDirPerm); err != nil {
		return fmt.Errorf("failed to create device directory: %w", err)
	}

	changesCount := 0
	
	// Check if info.json needs updating (excluding last_seen which is tracked in memory)
	infoPath := filepath.Join(deviceDir, "info.json")
	
	// Read existing info to check if we need to update
	needsInfoUpdate := false
	existingInfo, err := os.ReadFile(infoPath)
	if err != nil {
		// File doesn't exist, needs update
		needsInfoUpdate = true
	} else {
		// Parse existing info to check if basic info changed
		var existing struct {
			HardwareID string `json:"hardware_id"`
			Hostname   string `json:"hostname"`
			User       string `json:"user"`
		}
		if err := json.Unmarshal(existingInfo, &existing); err != nil {
			needsInfoUpdate = true
		} else {
			// Update only if basic info changed (NOT last_seen)
			if existing.HardwareID != device.HardwareID ||
				existing.Hostname != device.Hostname ||
				existing.User != device.User {
				needsInfoUpdate = true
			}
		}
	}
	
	if needsInfoUpdate {
		// Don't store last_seen in git - it's tracked in memory
		infoData, err := json.MarshalIndent(map[string]any{
			"hardware_id": device.HardwareID,
			"hostname":    device.Hostname,
			"user":        device.User,
		}, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal device info: %w", err)
		}
		
		if err := os.WriteFile(infoPath, infoData, infoFilePerm); err != nil {
			return fmt.Errorf("failed to write device info: %w", err)
		}
		changesCount++
	}
	for checkName, check := range device.Checks {
		checkPath := filepath.Join(deviceDir, fmt.Sprintf("%s.json", sanitizeID(checkName)))

		// Marshal check to JSON
		checkData, err := json.MarshalIndent(check, "", "  ")
		if err != nil {
			log.Printf("[WARN] Failed to marshal check %s for device %s: %v", checkName, device.HardwareID, err)
			continue
		}

		existingContent, err := os.ReadFile(checkPath)
		if err != nil {
			// File doesn't exist, we'll write it
			existingContent = nil
		}
		existingHash := sha256.Sum256(existingContent)
		newHash := sha256.Sum256(checkData)

		if existingHash != newHash {
			changesCount++
			if err := os.WriteFile(checkPath, checkData, checkFilePerm); err != nil {
				log.Printf("[WARN] Failed to write check %s for device %s: %v", checkName, device.HardwareID, err)
				continue
			}
			// Log what's being saved
			log.Printf("[DEBUG] Updated %s: stdout=%d bytes, stderr=%d bytes, exit=%d", 
				checkPath, len(check.Stdout), len(check.Stderr), check.ExitCode)
		}
	}

	log.Printf("[DEBUG] Device %s: %d checks updated", device.HardwareID, changesCount)

	// Skip git operations if nothing changed
	if changesCount == 0 {
		log.Printf("[DEBUG] Device %s: no changes detected, skipping git operations", device.HardwareID)
		return nil
	}

	// Git operations with retry logic
	if err := retry.Do(func() error {
		return s.runGitCommand(ctx, "add", "-A")
	}, retry.Attempts(maxRetries), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff)); err != nil {
		log.Printf("[WARN] Git add failed for device %s: %v", device.HardwareID, err)
		// Continue without git operations - graceful degradation
		return nil
	}

	status, err := retry.DoWithData(func() (string, error) {
		return s.runGitCommandOutput(ctx, "status", "--porcelain")
	}, retry.Attempts(maxRetries), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff))
	if err != nil {
		log.Printf("[WARN] Git status failed for device %s: %v", device.HardwareID, err)
		return nil
	}

	if strings.TrimSpace(status) != "" {
		commitMsg := fmt.Sprintf("Update device %s (%s)", device.HardwareID, device.Hostname)
		if err := retry.Do(func() error {
			return s.runGitCommand(ctx, "commit", "-m", commitMsg)
		}, retry.Attempts(maxRetries), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff)); err != nil {
			log.Printf("[WARN] Git commit failed for device %s: %v", device.HardwareID, err)
			return nil
		}

		if !s.isLocalRepo() {
			if err := retry.Do(func() error {
				return s.runGitCommand(ctx, "push")
			}, retry.Attempts(maxRetries), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff)); err != nil {
				log.Printf("[WARN] Git push failed for device %s: %v", device.HardwareID, err)
				// Don't return error - push failure is not critical
			} else {
				log.Printf("[DEBUG] Device %s pushed to remote repository", device.HardwareID)
			}
		}

		log.Printf("[INFO] Device %s saved and committed (%d changes) in %v",
			device.HardwareID, changesCount, time.Since(start))
	} else {
		log.Printf("[DEBUG] Device %s: no changes detected", device.HardwareID)
	}

	return nil
}

// ListDevices returns all devices from the Git repository.
func (s *Store) ListDevices(ctx context.Context) ([]*types.Device, error) {
	start := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Printf("[DEBUG] Loading devices from git repository")

	if !s.isLocalRepo() {
		log.Printf("[DEBUG] Pulling latest changes from remote repository")
		if err := retry.Do(func() error {
			return s.runGitCommand(ctx, "pull")
		}, retry.Attempts(maxRetries), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff)); err != nil {
			log.Printf("[WARN] Git pull failed: %v (continuing with local data)", err)
		} else {
			log.Printf("[DEBUG] Git pull completed successfully")
		}
	}

	devicesDir := filepath.Join(s.repoPath, "devices")
	entries, err := os.ReadDir(devicesDir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[INFO] No devices directory found, returning empty list")
			return []*types.Device{}, nil
		}
		return nil, fmt.Errorf("failed to read devices directory: %w", err)
	}

	var devices []*types.Device
	failedCount := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		device, err := s.loadDevice(ctx, entry.Name())
		if err != nil {
			failedCount++
			log.Printf("[WARN] Failed to load device %s: %v", entry.Name(), err)
			continue
		}
		devices = append(devices, device)
	}

	log.Printf("[INFO] Loaded %d devices (%d failed) from git repository in %v",
		len(devices), failedCount, time.Since(start))

	return devices, nil
}

func (s *Store) loadDevice(_ context.Context, dirName string) (*types.Device, error) {
	deviceDir := filepath.Join(s.repoPath, "devices", dirName)

	infoPath := filepath.Join(deviceDir, "info.json")
	infoData, err := os.ReadFile(infoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read device info: %w", err)
	}

	var info struct {
		HardwareID string `json:"hardware_id"`
		Hostname   string `json:"hostname"`
		User       string `json:"user"`
	}
	if err := json.Unmarshal(infoData, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal device info: %w", err)
	}

	device := &types.Device{
		HardwareID: info.HardwareID,
		Hostname:   info.Hostname,
		User:       info.User,
		LastSeen:   time.Time{}, // Will be set from file timestamps
		Checks:     make(map[string]types.Check),
	}

	// Get last_seen from the most recent file modification time in the directory
	entries, err := os.ReadDir(deviceDir)
	if err != nil {
		return device, err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(deviceDir, entry.Name())
		
		// Track the most recent modification time
		if stat, err := os.Stat(filePath); err == nil {
			if stat.ModTime().After(device.LastSeen) {
				device.LastSeen = stat.ModTime()
			}
		}
		
		// Skip loading info.json as check (already loaded above)
		if entry.Name() == "info.json" {
			continue
		}

		checkName := strings.TrimSuffix(entry.Name(), ".json")
		content, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("Failed to read check %s: %v", checkName, err)
			continue
		}

		var check types.Check
		if err := json.Unmarshal(content, &check); err != nil {
			log.Printf("Failed to unmarshal check %s: %v", checkName, err)
			continue
		}

		device.Checks[checkName] = check
	}

	return device, nil
}

func (s *Store) runGitCommand(ctx context.Context, args ...string) error {
	return s.runGitCommandInDir(ctx, s.repoPath, args...)
}

func (s *Store) runGitCommandWithRetry(ctx context.Context, args ...string) error {
	return s.runGitCommandInDirWithRetry(ctx, s.repoPath, args...)
}

func (s *Store) runGitCommandInDirWithRetry(ctx context.Context, dir string, args ...string) error {
	return retry.Do(func() error {
		return s.runGitCommandInDir(ctx, dir, args...)
	}, retry.Attempts(maxRetries), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff))
}

func (*Store) runGitCommandInDir(ctx context.Context, dir string, args ...string) error {
	// Add timeout to prevent hanging git operations
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()

	start := time.Now()
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}

	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	if err != nil {
		log.Printf("[DEBUG] Git command failed in %v: git %v (error: %v, output: %s)",
			duration, args, err, string(output))
		return fmt.Errorf("git %v failed: %w\n%s", args, err, output)
	}

	log.Printf("[DEBUG] Git command completed in %v: git %v", duration, args)
	return nil
}

func (s *Store) runGitCommandOutput(ctx context.Context, args ...string) (string, error) {
	// Add timeout to prevent hanging git operations
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()

	start := time.Now()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = s.repoPath

	output, err := cmd.Output()
	duration := time.Since(start)

	if err != nil {
		log.Printf("[DEBUG] Git output command failed in %v: git %v (error: %v)",
			duration, args, err)
		return "", fmt.Errorf("git %v failed: %w", args, err)
	}

	log.Printf("[DEBUG] Git output command completed in %v: git %v", duration, args)
	return string(output), nil
}

func sanitizeID(id string) string {
	// Security: Prevent path traversal by removing dangerous characters
	// Also prevent relative path components
	id = strings.ReplaceAll(id, "..", "")
	id = strings.ReplaceAll(id, "./", "")
	id = strings.ReplaceAll(id, "/", replacementChar)
	id = strings.ReplaceAll(id, "\\", replacementChar)
	id = strings.ReplaceAll(id, ":", replacementChar)
	id = strings.ReplaceAll(id, "*", replacementChar)
	id = strings.ReplaceAll(id, "?", replacementChar)
	id = strings.ReplaceAll(id, "\"", replacementChar)
	id = strings.ReplaceAll(id, "<", replacementChar)
	id = strings.ReplaceAll(id, ">", replacementChar)
	id = strings.ReplaceAll(id, "|", replacementChar)
	id = strings.ReplaceAll(id, " ", replacementChar)
	id = strings.ReplaceAll(id, "\x00", replacementChar) // Null bytes

	// Ensure ID is not empty after sanitization
	if id == "" || id == "-" || id == "--" {
		id = "unknown"
	}

	// Limit length to prevent filesystem issues
	if len(id) > 255 {
		id = id[:255]
	}

	return id
}
