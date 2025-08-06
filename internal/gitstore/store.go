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

// New creates a new Git-based store for device compliance data.
func New(ctx context.Context, gitURL string) (*Store, error) {
	tempDir := filepath.Join(os.TempDir(), fmt.Sprintf("gitmdm-%d", time.Now().Unix()))

	s := &Store{
		repoPath: tempDir,
		gitURL:   gitURL,
	}

	if err := s.initialize(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize git store: %w", err)
	}

	log.Printf("[INFO] Git store initialized: %s (repo: %s)", gitURL, s.repoPath)
	return s, nil
}

func (s *Store) initialize(ctx context.Context) error {
	start := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Printf("[INFO] Initializing git store for URL: %s", s.gitURL)

	if strings.HasPrefix(s.gitURL, "/") || strings.HasPrefix(s.gitURL, "./") {
		s.repoPath = s.gitURL
		log.Printf("[INFO] Using local repository: %s", s.repoPath)

		if _, err := os.Stat(filepath.Join(s.repoPath, ".git")); os.IsNotExist(err) {
			log.Printf("[INFO] Initializing new local git repository")
			if err := s.runGitCommandWithRetry(ctx, "init"); err != nil {
				return fmt.Errorf("failed to init local repository: %w", err)
			}
			if err := s.runGitCommandWithRetry(ctx, "config", "user.email", "gitmdm@localhost"); err != nil {
				return err
			}
			if err := s.runGitCommandWithRetry(ctx, "config", "user.name", "gitMDM"); err != nil {
				return err
			}
			log.Printf("[INFO] Local git repository initialized")
		} else {
			log.Printf("[INFO] Using existing local git repository")
		}
	} else {
		log.Printf("[INFO] Cloning remote repository: %s", s.gitURL)
		if err := s.runGitCommandInDirWithRetry(ctx, "", "clone", s.gitURL, s.repoPath); err != nil {
			return fmt.Errorf("failed to clone repository: %w", err)
		}
		if err := s.runGitCommandWithRetry(ctx, "config", "user.email", "gitmdm@localhost"); err != nil {
			return err
		}
		if err := s.runGitCommandWithRetry(ctx, "config", "user.name", "gitMDM"); err != nil {
			return err
		}
		log.Printf("[INFO] Remote repository cloned successfully")
	}

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

	log.Printf("[DEBUG] Saving device %s (%d checks) to %s", device.HardwareID, len(device.Checks), deviceDir)

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

	infoPath := filepath.Join(deviceDir, "info.json")
	infoData, err := json.MarshalIndent(map[string]any{
		"hardware_id": device.HardwareID,
		"hostname":    device.Hostname,
		"user":        device.User,
		"last_seen":   device.LastSeen,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal device info: %w", err)
	}

	if err := os.WriteFile(infoPath, infoData, infoFilePerm); err != nil {
		return fmt.Errorf("failed to write device info: %w", err)
	}

	changesCount := 0
	for checkName, check := range device.Checks {
		checkPath := filepath.Join(deviceDir, fmt.Sprintf("%s.md", sanitizeID(checkName)))

		content := fmt.Sprintf("# %s\n\n```\n%s\n```\n", check.Command, check.Output)

		existingContent, err := os.ReadFile(checkPath)
		if err != nil {
			// File doesn't exist, we'll write it
			existingContent = nil
		}
		existingHash := sha256.Sum256(existingContent)
		newHash := sha256.Sum256([]byte(content))

		if existingHash != newHash {
			changesCount++
			if err := os.WriteFile(checkPath, []byte(content), checkFilePerm); err != nil {
				log.Printf("[WARN] Failed to write check %s for device %s: %v", checkName, device.HardwareID, err)
				continue
			}
		}
	}

	log.Printf("[DEBUG] Device %s: %d checks updated", device.HardwareID, changesCount)

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

		if !strings.HasPrefix(s.gitURL, "/") && !strings.HasPrefix(s.gitURL, "./") {
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

	if !strings.HasPrefix(s.gitURL, "/") && !strings.HasPrefix(s.gitURL, "./") {
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
		LastSeen   time.Time `json:"last_seen"`
		HardwareID string    `json:"hardware_id"`
		Hostname   string    `json:"hostname"`
		User       string    `json:"user"`
	}
	if err := json.Unmarshal(infoData, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal device info: %w", err)
	}

	device := &types.Device{
		HardwareID: info.HardwareID,
		Hostname:   info.Hostname,
		User:       info.User,
		LastSeen:   info.LastSeen,
		Checks:     make(map[string]types.Check),
	}

	entries, err := os.ReadDir(deviceDir)
	if err != nil {
		return device, err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") || entry.Name() == "info.json" {
			continue
		}

		checkName := strings.TrimSuffix(entry.Name(), ".md")
		checkPath := filepath.Join(deviceDir, entry.Name())

		content, err := os.ReadFile(checkPath)
		if err != nil {
			log.Printf("Failed to read check %s: %v", checkName, err)
			continue
		}

		lines := strings.Split(string(content), "\n")
		var command, output string
		var inOutput bool

		for _, line := range lines {
			switch {
			case strings.HasPrefix(line, "# "):
				command = strings.TrimPrefix(line, "# ")
			case line == "```":
				if inOutput {
					return device, nil // Early return to exit the loop properly
				}
				inOutput = true
			case inOutput:
				if output != "" {
					output += "\n"
				}
				output += line
			default:
				// Do nothing for other lines
			}
		}

		device.Checks[checkName] = types.Check{
			Command: command,
			Output:  output,
		}
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
	return id
}
