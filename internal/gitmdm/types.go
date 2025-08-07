// Package gitmdm defines shared data structures for gitMDM.
package gitmdm

import "time"

// Device represents a monitored device with its compliance status.
type Device struct {
	LastSeen   time.Time        `json:"last_seen"`
	LastIP     string           `json:"last_ip"`
	Checks     map[string]Check `json:"checks"`
	HardwareID string           `json:"hardware_id"`
	Hostname   string           `json:"hostname"`
	User       string           `json:"user"`
	// In-memory only fields (not persisted to git)
	SystemUptime  string `json:"-"`
	CPULoad       string `json:"-"`
	LoggedInUsers string `json:"-"`
}

// CommandOutput represents the output from a single command or file check.
type CommandOutput struct {
	Command     string   `json:"command,omitempty"`      // Command that was executed
	File        string   `json:"file,omitempty"`         // File that was read
	Stdout      string   `json:"stdout,omitempty"`       // Command stdout or file contents
	Stderr      string   `json:"stderr,omitempty"`       // Command stderr
	ExitCode    int      `json:"exit_code,omitempty"`    // Command exit code
	FileMissing bool     `json:"file_missing,omitempty"` // True if file doesn't exist
	Skipped     bool     `json:"skipped,omitempty"`      // True if command was skipped (not found)
	Failed      bool     `json:"failed,omitempty"`       // True if this specific check failed
	FailReason  string   `json:"fail_reason,omitempty"`  // Why this specific check failed
	Remediation []string `json:"remediation,omitempty"`  // Remediation steps for this failure
}

// Check represents a compliance check result, potentially with multiple command outputs.
type Check struct {
	Timestamp   time.Time       `json:"-"`                     // Not stored in JSON, set from file mtime
	Outputs     []CommandOutput `json:"outputs"`               // All command outputs for this check
	Status      string          `json:"status"`                // "pass", "fail", or "n/a"
	Reason      string          `json:"reason"`                // Human-readable explanation of the status
	Remediation []string        `json:"remediation,omitempty"` // Steps to fix if failed
}

// DeviceReport represents a compliance report sent by an agent.
type DeviceReport struct {
	Timestamp     time.Time        `json:"timestamp"`
	Checks        map[string]Check `json:"checks"`
	HardwareID    string           `json:"hardware_id"`
	Hostname      string           `json:"hostname"`
	User          string           `json:"user"`
	SystemUptime  string           `json:"system_uptime,omitempty"`
	CPULoad       string           `json:"cpu_load,omitempty"`
	LoggedInUsers string           `json:"logged_in_users,omitempty"`
}

// IsValidCheckName validates that a check name contains only safe characters.
func IsValidCheckName(name string) bool {
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
