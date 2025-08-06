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

// Check represents a single compliance check result.
type Check struct {
	Timestamp time.Time `json:"-"` // Not stored in JSON, set from file mtime
	Command   string    `json:"command"`
	Stdout    string    `json:"stdout"`
	Stderr    string    `json:"stderr"`
	ExitCode  int       `json:"exit_code"`
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
