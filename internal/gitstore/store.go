// Package gitstore provides Git-based storage for device compliance data.
package gitstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"gitmdm/internal/gitmdm"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/codeGROOVE-dev/retry"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

const (
	// Directory permissions.
	deviceDirPerm = 0o750
	repoDirPerm   = 0o750
	// File permissions.
	infoFilePerm  = 0o600
	checkFilePerm = 0o600
	// Retry configuration for git operations.
	maxRetries     = 3
	initialBackoff = 1 * time.Second
	maxBackoff     = 2 * time.Minute // Wait up to 2 minutes with exponential backoff
	// Directory names.
	devicesDir = "devices"
)

// Store provides Git-based storage for device compliance data using go-git.
type Store struct {
	auth     transport.AuthMethod
	repo     *git.Repository
	gitURL   string
	repoPath string
	mu       sync.Mutex
}

// NewLocal creates a store using a local git repository.
// If the directory doesn't exist or is not a git repository, it will initialize one.
func NewLocal(ctx context.Context, localPath string) (*Store, error) {
	absPath, err := filepath.Abs(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(absPath, repoDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	// Check if it's already a git repository
	var repo *git.Repository
	if _, err := os.Stat(filepath.Join(absPath, ".git")); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to check git repository: %w", err)
		}
		// Initialize new repository
		log.Printf("[INFO] Initializing new git repository at %s", absPath)
		repo, err = git.PlainInit(absPath, false)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize git repository: %w", err)
		}
		// No initial commit needed - first device will create directory structure
	} else {
		// Open existing repository
		repo, err = git.PlainOpen(absPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open git repository: %w", err)
		}
	}

	s := &Store{
		repoPath: absPath,
		repo:     repo,
	}

	// Check if remote is configured using go-git
	remotes, err := repo.Remotes()
	if err == nil && len(remotes) > 0 {
		// Has remote configured - enable push/pull
		s.gitURL = "remote"
		log.Printf("[INFO] Git store initialized with local repository: %s (remote configured, will push/pull)", absPath)
	} else {
		// No remote - work locally only
		s.gitURL = absPath
		log.Printf("[INFO] Git store initialized with local repository: %s (no remote, local only)", absPath)
	}

	// Create devices directory if it doesn't exist
	devicesDirPath := filepath.Join(s.repoPath, devicesDir)
	if err := os.MkdirAll(devicesDirPath, repoDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create devices directory: %w", err)
	}

	return s, nil
}

// NewRemote creates a store by cloning a repository to a temp directory.
func NewRemote(ctx context.Context, gitURL string) (*Store, error) {
	// Check if this is a local path
	if strings.HasPrefix(gitURL, "/") || strings.HasPrefix(gitURL, "./") || strings.HasPrefix(gitURL, "../") {
		// For local paths, use NewLocal directly on the path
		return NewLocal(ctx, gitURL)
	}

	// Security: Validate git URL
	// Allow SSH, HTTPS, HTTP URLs, or local file paths
	if !strings.HasPrefix(gitURL, "git@") &&
		!strings.HasPrefix(gitURL, "https://") &&
		!strings.HasPrefix(gitURL, "http://") &&
		!strings.HasPrefix(gitURL, "/") &&
		!strings.HasPrefix(gitURL, "./") &&
		!strings.HasPrefix(gitURL, "../") {
		return nil, errors.New("invalid git URL format")
	}

	// Create secure temp directory
	tempDir, err := os.MkdirTemp("", "gitmdm-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	// For remote URLs, we need to clone
	log.Printf("[INFO] Cloning repository from %s to %s", gitURL, tempDir)

	var repo *git.Repository
	var auth transport.AuthMethod

	// Setup authentication if needed
	if strings.HasPrefix(gitURL, "https://") || strings.HasPrefix(gitURL, "http://") {
		// Could add HTTP basic auth here if needed
		auth = nil
	} else if strings.HasPrefix(gitURL, "git@") || strings.Contains(gitURL, ":") {
		// SSH auth - will use SSH agent or default keys
		auth = nil // go-git will try default SSH auth
	}

	err = retry.Do(func() error {
		cloneOptions := &git.CloneOptions{
			URL:      gitURL,
			Progress: nil,
		}
		if auth != nil {
			cloneOptions.Auth = auth
		}

		var cloneErr error
		repo, cloneErr = git.PlainClone(tempDir, false, cloneOptions)
		return cloneErr
	}, retry.Attempts(maxRetries), retry.DelayType(retry.FullJitterBackoffDelay), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff))
	if err != nil {
		if removeErr := os.RemoveAll(tempDir); removeErr != nil {
			log.Printf("[WARN] Failed to clean up temp directory %s: %v", tempDir, removeErr)
		}
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}

	// Configure git user
	cfg, err := repo.Config()
	if err == nil {
		cfg.User.Name = "gitMDM"
		cfg.User.Email = "gitmdm@localhost"
		if err := repo.SetConfig(cfg); err != nil {
			log.Printf("[WARN] Failed to set git config: %v", err)
		}
	}

	s := &Store{
		repoPath: tempDir,
		gitURL:   gitURL,
		repo:     repo,
		auth:     auth,
	}

	// Create devices directory if needed
	devicesDirPath := filepath.Join(s.repoPath, devicesDir)
	if err := os.MkdirAll(devicesDirPath, repoDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create devices directory: %w", err)
	}

	log.Printf("[INFO] Git store initialized with remote: %s", gitURL)
	return s, nil
}

// SaveDevice saves or updates a device's compliance data.
func (s *Store) SaveDevice(ctx context.Context, device *gitmdm.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	deviceDir := filepath.Join(s.repoPath, devicesDir, sanitizeID(device.HardwareID))
	if err := os.MkdirAll(deviceDir, deviceDirPerm); err != nil {
		return fmt.Errorf("failed to create device directory: %w", err)
	}

	// Save device info
	infoPath := filepath.Join(deviceDir, "info.json")
	deviceInfo := struct {
		HardwareID string    `json:"hardware_id"`
		Hostname   string    `json:"hostname"`
		User       string    `json:"user"`
		LastSeen   time.Time `json:"last_seen"`
		LastIP     string    `json:"last_ip"`
	}{
		HardwareID: device.HardwareID,
		Hostname:   device.Hostname,
		User:       device.User,
		LastSeen:   device.LastSeen,
		LastIP:     device.LastIP,
	}

	infoData, err := json.MarshalIndent(deviceInfo, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal device info: %w", err)
	}

	if err := os.WriteFile(infoPath, infoData, infoFilePerm); err != nil {
		return fmt.Errorf("failed to write device info: %w", err)
	}

	// Save each check
	changesCount := 0
	for checkName, check := range device.Checks {
		checkPath := filepath.Join(deviceDir, fmt.Sprintf("%s.json", sanitizeID(checkName)))

		// Read existing check to compare
		existingData, err := os.ReadFile(checkPath)
		if err != nil && !os.IsNotExist(err) {
			log.Printf("[WARN] Failed to read existing check %s: %v", checkPath, err)
		}

		checkData, err := json.MarshalIndent(check, "", "  ")
		if err != nil {
			log.Printf("[WARN] Failed to marshal check %s: %v", checkName, err)
			continue
		}

		// Only write if content changed
		// Simple byte comparison is sufficient since we control the JSON marshaling format
		if !bytes.Equal(existingData, checkData) {
			if err := os.WriteFile(checkPath, checkData, checkFilePerm); err != nil {
				log.Printf("[WARN] Failed to write check %s: %v", checkName, err)
				continue
			}
			changesCount++
		}
	}

	log.Printf("[DEBUG] Device %s: %d checks updated", device.HardwareID, changesCount)

	// Skip git operations if nothing changed
	if changesCount == 0 {
		log.Printf("[DEBUG] Device %s: no changes detected, skipping git operations", device.HardwareID)
		return nil
	}

	// Git operations using go-git
	w, err := s.repo.Worktree()
	if err != nil {
		log.Printf("[WARN] Failed to get worktree for device %s: %v", device.HardwareID, err)
		return nil
	}

	// Add all changes
	retryCount := 0
	if err := retry.Do(func() error {
		retryCount++
		if retryCount > 1 {
			log.Printf("[DEBUG] Retry attempt %d/%d for git add (device %s)", retryCount, maxRetries, device.HardwareID)
		}
		return w.AddGlob("devices/*")
	},
		retry.Attempts(maxRetries),
		retry.DelayType(retry.FullJitterBackoffDelay),
		retry.Delay(initialBackoff),
		retry.MaxDelay(maxBackoff)); err != nil {
		log.Printf("[WARN] Git add failed for device %s after %d retries: %v", device.HardwareID, maxRetries, err)
		return nil
	}

	// Check status
	status, err := w.Status()
	if err != nil {
		log.Printf("[WARN] Git status failed for device %s: %v", device.HardwareID, err)
		return nil
	}

	if !status.IsClean() {
		commitMsg := fmt.Sprintf("Update device %s (%s)", device.HardwareID, device.Hostname)

		// Create commit
		if err := retry.Do(func() error {
			_, err := w.Commit(commitMsg, &git.CommitOptions{
				Author: &object.Signature{
					Name:  "GitMDM",
					Email: "gitmdm@localhost",
					When:  time.Now(),
				},
			})
			return err
		},
			retry.Attempts(maxRetries),
			retry.DelayType(retry.FullJitterBackoffDelay),
			retry.Delay(initialBackoff),
			retry.MaxDelay(maxBackoff)); err != nil {
			log.Printf("[WARN] Git commit failed for device %s: %v", device.HardwareID, err)
			return nil
		}

		// Push to remote if configured
		if s.gitURL != s.repoPath && s.gitURL != "" {
			if err := retry.Do(func() error {
				pushOptions := &git.PushOptions{}
				if s.auth != nil {
					pushOptions.Auth = s.auth
				}
				err := s.repo.Push(pushOptions)
				if errors.Is(err, git.NoErrAlreadyUpToDate) {
					return nil
				}
				return err
			},
				retry.Attempts(maxRetries),
				retry.DelayType(retry.FullJitterBackoffDelay),
				retry.Delay(initialBackoff),
				retry.MaxDelay(maxBackoff)); err != nil {
				log.Printf("[WARN] Git push failed for device %s: %v", device.HardwareID, err)
			} else {
				log.Printf("[DEBUG] Git push successful for device %s", device.HardwareID)
			}
		}
	} else {
		log.Printf("[DEBUG] No changes to commit for device %s", device.HardwareID)
	}

	return nil
}

// LoadDevices loads all devices from the git repository.
func (s *Store) LoadDevices(ctx context.Context) ([]*gitmdm.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Print("[DEBUG] Loading devices from git repository")

	// Pull from remote if configured
	if s.gitURL != s.repoPath && s.gitURL != "" {
		log.Print("[DEBUG] Pulling latest changes from remote repository")

		w, err := s.repo.Worktree()
		if err != nil {
			log.Printf("[WARN] Failed to get worktree for pull: %v", err)
		} else {
			pullOptions := &git.PullOptions{}
			if s.auth != nil {
				pullOptions.Auth = s.auth
			}

			err = retry.Do(func() error {
				err := w.Pull(pullOptions)
				if errors.Is(err, git.NoErrAlreadyUpToDate) {
					return nil
				}
				return err
			}, retry.Attempts(maxRetries), retry.DelayType(retry.FullJitterBackoffDelay), retry.Delay(initialBackoff), retry.MaxDelay(maxBackoff))

			if err != nil {
				log.Printf("[WARN] Git pull failed: %v (continuing with local data)", err)
			} else {
				log.Print("[DEBUG] Git pull completed successfully")
			}
		}
	}

	devicesDirPath := filepath.Join(s.repoPath, devicesDir)
	entries, err := os.ReadDir(devicesDirPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Print("[INFO] No devices directory found, returning empty list")
			return []*gitmdm.Device{}, nil
		}
		return nil, fmt.Errorf("failed to read devices directory: %w", err)
	}

	var devices []*gitmdm.Device
	failedCount := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Load device
		dirName := entry.Name()
		deviceDir := filepath.Join(s.repoPath, devicesDir, dirName)

		infoPath := filepath.Join(deviceDir, "info.json")
		infoData, err := os.ReadFile(infoPath)
		if err != nil {
			log.Printf("[WARN] Failed to read device info for %s: %v", dirName, err)
			failedCount++
			continue
		}

		var deviceInfo struct {
			HardwareID string    `json:"hardware_id"`
			Hostname   string    `json:"hostname"`
			User       string    `json:"user"`
			LastSeen   time.Time `json:"last_seen"`
			LastIP     string    `json:"last_ip"`
		}

		if err := json.Unmarshal(infoData, &deviceInfo); err != nil {
			log.Printf("[WARN] Failed to unmarshal device info for %s: %v", dirName, err)
			failedCount++
			continue
		}

		device := &gitmdm.Device{
			HardwareID: deviceInfo.HardwareID,
			Hostname:   deviceInfo.Hostname,
			User:       deviceInfo.User,
			LastSeen:   deviceInfo.LastSeen,
			LastIP:     deviceInfo.LastIP,
			Checks:     make(map[string]gitmdm.Check),
		}

		// Load checks
		checkFiles, err := os.ReadDir(deviceDir)
		if err != nil {
			log.Printf("[WARN] Failed to read checks for device %s: %v", deviceInfo.HardwareID, err)
		} else {
			for _, checkFile := range checkFiles {
				if checkFile.IsDir() || !strings.HasSuffix(checkFile.Name(), ".json") || checkFile.Name() == "info.json" {
					continue
				}

				checkPath := filepath.Join(deviceDir, checkFile.Name())
				checkData, err := os.ReadFile(checkPath)
				if err != nil {
					log.Printf("[WARN] Failed to read check %s for device %s: %v",
						checkFile.Name(), deviceInfo.HardwareID, err)
					continue
				}

				var check gitmdm.Check
				if err := json.Unmarshal(checkData, &check); err != nil {
					log.Printf("[WARN] Failed to unmarshal check %s for device %s: %v",
						checkFile.Name(), deviceInfo.HardwareID, err)
					continue
				}

				// Get check timestamp from file modification time
				if info, err := os.Stat(checkPath); err == nil {
					check.Timestamp = info.ModTime()
				}

				checkName := strings.TrimSuffix(checkFile.Name(), ".json")
				device.Checks[checkName] = check
			}
		}

		devices = append(devices, device)
	}

	log.Printf("[INFO] Loaded %d devices (%d failed) from git repository", len(devices), failedCount)
	return devices, nil
}

// sanitizeID converts a device ID to a safe directory name.
func sanitizeID(id string) string {
	// First, handle special cases that need hashing
	if id == "" || id == ".." || id == "./" || id == "." {
		hash := sha256.Sum256([]byte(id))
		return "id-" + hex.EncodeToString(hash[:8])
	}

	// Remove any leading path traversal attempts
	cleaned := id
	// Remove leading ../ sequences
	for strings.HasPrefix(cleaned, "../") {
		cleaned = cleaned[3:]
	}
	// Remove leading ./ sequences
	for strings.HasPrefix(cleaned, "./") {
		cleaned = cleaned[2:]
	}

	var sanitized strings.Builder
	for _, r := range cleaned {
		switch {
		case r >= 'a' && r <= 'z':
			sanitized.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			sanitized.WriteRune(r)
		case r >= '0' && r <= '9':
			sanitized.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			sanitized.WriteRune(r)
		default:
			sanitized.WriteRune('-')
		}
	}

	result := sanitized.String()

	// Remove leading/trailing dashes and underscores
	result = strings.Trim(result, "-_")

	// Security: Prevent directory traversal
	result = strings.ReplaceAll(result, "..", "-")
	result = strings.ReplaceAll(result, "//", "-")

	// Ensure ID is not empty after sanitization
	if result == "" || result == "-" || result == "_" {
		hash := sha256.Sum256([]byte(id))
		result = "id-" + hex.EncodeToString(hash[:8])
	}

	// Limit length
	const maxIDLength = 100
	if len(result) > maxIDLength {
		result = result[:maxIDLength]
	}

	return result
}
