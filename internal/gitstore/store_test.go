package gitstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitmdm/internal/types"
)

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal-id", "normal-id"},
		{"../../../etc/passwd", "etc-passwd"},
		{"id/with/slashes", "id-with-slashes"},
		{"id\\with\\backslashes", "id-with-backslashes"},
		{"id:with:colons", "id-with-colons"},
		{"id with spaces", "id-with-spaces"},
		{"id<with>special*chars?", "id-with-special-chars"},
		{"", "unknown"},
		{"..", "unknown"},
		{"./", "unknown"},
		{strings.Repeat("a", 300), strings.Repeat("a", 255)},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeID(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNewStore(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	localPath := filepath.Join(tempDir, "test-repo")

	// Test local repository creation
	store, err := New(ctx, localPath)
	if err != nil {
		t.Fatalf("Failed to create local store: %v", err)
	}
	if store == nil {
		t.Fatal("Store is nil")
	}

	// Verify repository was initialized
	gitDir := filepath.Join(localPath, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		t.Error("Git repository was not initialized")
	}

	// Verify devices directory was created
	devicesDir := filepath.Join(localPath, "devices")
	if _, err := os.Stat(devicesDir); os.IsNotExist(err) {
		t.Error("Devices directory was not created")
	}
}

func TestSaveAndLoadDevice(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	localPath := filepath.Join(tempDir, "test-repo")

	store, err := New(ctx, localPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Create test device
	device := &types.Device{
		HardwareID: "test-device-123",
		Hostname:   "test-host",
		User:       "test-user",
		LastSeen:   time.Now(),
		Checks: map[string]types.Check{
			"hostname": {
				Command:  "hostname",
				Stdout:   "test-host.local",
				Stderr:   "",
				ExitCode: 0,
			},
			"uname": {
				Command:  "uname -a",
				Stdout:   "Linux test-host 5.10.0",
				Stderr:   "",
				ExitCode: 0,
			},
		},
	}

	// Save device
	if err := store.SaveDevice(ctx, device); err != nil {
		t.Fatalf("Failed to save device: %v", err)
	}

	// List devices
	devices, err := store.ListDevices(ctx)
	if err != nil {
		t.Fatalf("Failed to list devices: %v", err)
	}

	if len(devices) != 1 {
		t.Fatalf("Expected 1 device, got %d", len(devices))
	}

	// Verify loaded device
	loaded := devices[0]
	if loaded.HardwareID != device.HardwareID {
		t.Errorf("HardwareID mismatch: got %s, want %s", loaded.HardwareID, device.HardwareID)
	}
	if loaded.Hostname != device.Hostname {
		t.Errorf("Hostname mismatch: got %s, want %s", loaded.Hostname, device.Hostname)
	}
	if loaded.User != device.User {
		t.Errorf("User mismatch: got %s, want %s", loaded.User, device.User)
	}
	if len(loaded.Checks) != len(device.Checks) {
		t.Errorf("Checks count mismatch: got %d, want %d", len(loaded.Checks), len(device.Checks))
	}

	// Verify checks content
	for name, check := range device.Checks {
		loadedCheck, exists := loaded.Checks[name]
		if !exists {
			t.Errorf("Check %s not found in loaded device", name)
			continue
		}
		if loadedCheck.Command != check.Command {
			t.Errorf("Check %s command mismatch: got %s, want %s", name, loadedCheck.Command, check.Command)
		}
		if loadedCheck.Stdout != check.Stdout {
			t.Errorf("Check %s stdout mismatch: got %s, want %s", name, loadedCheck.Stdout, check.Stdout)
		}
		if loadedCheck.ExitCode != check.ExitCode {
			t.Errorf("Check %s exit code mismatch: got %d, want %d", name, loadedCheck.ExitCode, check.ExitCode)
		}
	}
}

func TestPathTraversalPrevention(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	localPath := filepath.Join(tempDir, "test-repo")

	store, err := New(ctx, localPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Try to save device with path traversal attempt
	device := &types.Device{
		HardwareID: "../../../etc/passwd",
		Hostname:   "evil-host",
		User:       "evil-user",
		LastSeen:   time.Now(),
		Checks: map[string]types.Check{
			"../../../evil": {
				Command:  "evil command",
				Stdout:   "evil output",
				Stderr:   "",
				ExitCode: 0,
			},
		},
	}

	// This should succeed but sanitize the paths
	if err := store.SaveDevice(ctx, device); err != nil {
		t.Fatalf("Failed to save device: %v", err)
	}

	// Verify the file was saved in the correct location (sanitized)
	expectedDir := filepath.Join(localPath, "devices", "etc-passwd")
	if _, err := os.Stat(expectedDir); os.IsNotExist(err) {
		t.Error("Device directory was not created in expected location")
	}

	// Verify no files were created outside the repo
	etcPasswd := "/etc/passwd.md"
	if _, err := os.Stat(etcPasswd); err == nil {
		t.Fatal("Path traversal was not prevented!")
	}
}

func TestConcurrentSaves(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	localPath := filepath.Join(tempDir, "test-repo")

	store, err := New(ctx, localPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Run concurrent saves
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			device := &types.Device{
				HardwareID: fmt.Sprintf("device-%d", id),
				Hostname:   fmt.Sprintf("host-%d", id),
				User:       "test-user",
				LastSeen:   time.Now(),
				Checks:     map[string]types.Check{},
			}
			if err := store.SaveDevice(ctx, device); err != nil {
				t.Errorf("Failed to save device %d: %v", id, err)
			}
			done <- true
		}(i)
	}

	// Wait for all saves to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all devices were saved
	devices, err := store.ListDevices(ctx)
	if err != nil {
		t.Fatalf("Failed to list devices: %v", err)
	}

	if len(devices) != 10 {
		t.Errorf("Expected 10 devices, got %d", len(devices))
	}
}
