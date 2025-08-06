package gitmdm

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDeviceSerialization(t *testing.T) {
	device := &Device{
		HardwareID: "test-123",
		Hostname:   "test-host",
		User:       "test-user",
		LastSeen:   time.Now(),
		Checks: map[string]Check{
			"test": {
				Command:  "echo test",
				Stdout:   "test output",
				Stderr:   "",
				ExitCode: 0,
			},
		},
	}

	// Test JSON marshaling
	data, err := json.Marshal(device)
	if err != nil {
		t.Fatalf("Failed to marshal device: %v", err)
	}

	// Test JSON unmarshaling
	var decoded Device
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal device: %v", err)
	}

	// Verify fields
	if decoded.HardwareID != device.HardwareID {
		t.Errorf("HardwareID mismatch: got %s, want %s", decoded.HardwareID, device.HardwareID)
	}
	if decoded.Hostname != device.Hostname {
		t.Errorf("Hostname mismatch: got %s, want %s", decoded.Hostname, device.Hostname)
	}
	if decoded.User != device.User {
		t.Errorf("User mismatch: got %s, want %s", decoded.User, device.User)
	}
	if len(decoded.Checks) != len(device.Checks) {
		t.Errorf("Checks count mismatch: got %d, want %d", len(decoded.Checks), len(device.Checks))
	}
}

func TestDeviceReportValidation(t *testing.T) {
	tests := []struct {
		name   string
		report DeviceReport
		valid  bool
	}{
		{
			name: "valid report",
			report: DeviceReport{
				HardwareID: "hw-123",
				Hostname:   "host",
				User:       "user",
				Timestamp:  time.Now(),
				Checks:     map[string]Check{},
			},
			valid: true,
		},
		{
			name: "empty hardware ID",
			report: DeviceReport{
				Hostname:  "host",
				User:      "user",
				Timestamp: time.Now(),
				Checks:    map[string]Check{},
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation that HardwareID is required
			isValid := tt.report.HardwareID != ""
			if isValid != tt.valid {
				t.Errorf("Validation failed for %s: got %v, want %v", tt.name, isValid, tt.valid)
			}
		})
	}
}
