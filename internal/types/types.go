// Package types defines shared data structures for gitMDM.
package types

import "time"

// Device represents a monitored device with its compliance status.
type Device struct {
	LastSeen   time.Time        `json:"last_seen"`
	LastIP     string           `json:"last_ip"`
	Checks     map[string]Check `json:"checks"`
	HardwareID string           `json:"hardware_id"`
	Hostname   string           `json:"hostname"`
	User       string           `json:"user"`
}

// Check represents a single compliance check result.
type Check struct {
	Command   string    `json:"command"`
	Stdout    string    `json:"stdout"`
	Stderr    string    `json:"stderr"`
	ExitCode  int       `json:"exit_code"`
	Timestamp time.Time `json:"-"` // Not stored in JSON, set from file mtime
}

// DeviceReport represents a compliance report sent by an agent.
type DeviceReport struct {
	Timestamp  time.Time        `json:"timestamp"`
	Checks     map[string]Check `json:"checks"`
	HardwareID string           `json:"hardware_id"`
	Hostname   string           `json:"hostname"`
	User       string           `json:"user"`
}
