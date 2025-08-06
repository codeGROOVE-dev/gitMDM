// Package viewmodels provides view models for the web UI templates.
package viewmodels

import (
	"gitmdm/internal/gitmdm"
	"sort"
	"strings"
	"time"
)

// DeviceListItem represents a device in the list view with compliance summary.
type DeviceListItem struct {
	HardwareID      string
	Hostname        string
	User            string
	OS              string
	Version         string
	LastSeen        time.Time
	PassCount       int
	FailCount       int
	NACount         int
	ComplianceScore float64
	ComplianceEmoji string
	ComplianceClass string
}

// DeviceListView represents the device list page view model with filters.
type DeviceListView struct {
	Devices     []DeviceListItem
	Search      string
	Status      string
	Page        int
	TotalPages  int
	Total       int
	HasPrevious bool
	HasNext     bool
}

// DeviceDetail represents the detailed device view with analysis results.
type DeviceDetail struct {
	*gitmdm.Device

	CheckResults      map[string]CheckResult
	SortedChecks      []string
	FailingChecks     []string
	PassingChecks     []string
	NAChecks          []string
	PassCount         int
	FailCount         int
	NACount           int
	ComplianceMessage string
}

// CheckResult represents the display info for a check.
type CheckResult struct {
	Status      string
	Reason      string
	Emoji       string
	Remediation []string
}

// BuildDeviceDetail creates a detailed view model for a single device.
func BuildDeviceDetail(device *gitmdm.Device) *DeviceDetail {
	detail := &DeviceDetail{
		Device:       device,
		CheckResults: make(map[string]CheckResult),
	}

	// Filter out checks that are more than 1 hour older than LastSeen
	staleThreshold := device.LastSeen.Add(-1 * time.Hour)

	// Process all checks
	for checkName, check := range device.Checks {
		// Skip stale checks that are too old
		if !check.Timestamp.IsZero() && check.Timestamp.Before(staleThreshold) {
			continue
		}
		var emoji string
		switch check.Status {
		case "pass":
			emoji = "✅"
			detail.PassCount++
		case "fail":
			emoji = "❌"
			detail.FailCount++
		default: // "n/a" or empty
			emoji = "➖"
			detail.NACount++
		}

		// For N/A checks, don't show "Unable to determine status" - it's noise
		reason := check.Reason
		if check.Status == "n/a" && (reason == "Unable to determine status" || reason == "Informational check - data collected") {
			reason = ""
		}

		detail.CheckResults[checkName] = CheckResult{
			Status:      check.Status,
			Reason:      reason,
			Emoji:       emoji,
			Remediation: check.Remediation,
		}
	}

	// Create sorted list of checks (failed first, then passed, then n/a)
	var checkNames []string
	var failingChecks []string
	var passingChecks []string
	var naChecks []string

	for checkName := range detail.CheckResults {
		checkNames = append(checkNames, checkName)

		// Categorize checks by status
		status := detail.CheckResults[checkName].Status
		switch status {
		case "fail":
			failingChecks = append(failingChecks, checkName)
		case "pass":
			passingChecks = append(passingChecks, checkName)
		default: // "n/a"
			naChecks = append(naChecks, checkName)
		}
	}

	sort.Slice(checkNames, func(i, j int) bool {
		statusI := detail.CheckResults[checkNames[i]].Status
		statusJ := detail.CheckResults[checkNames[j]].Status

		// Priority: fail > pass > n/a
		priority := map[string]int{"fail": 0, "pass": 1, "n/a": 2}

		if priority[statusI] != priority[statusJ] {
			return priority[statusI] < priority[statusJ]
		}

		// If same status, sort alphabetically
		return checkNames[i] < checkNames[j]
	})

	// Sort each category alphabetically
	sort.Strings(failingChecks)
	sort.Strings(passingChecks)
	sort.Strings(naChecks)

	detail.SortedChecks = checkNames
	detail.FailingChecks = failingChecks
	detail.PassingChecks = passingChecks
	detail.NAChecks = naChecks

	// Generate compliance message
	total := detail.PassCount + detail.FailCount
	if total == 0 {
		detail.ComplianceMessage = "No compliance checks to evaluate. Living dangerously!"
	} else {
		score := float64(detail.PassCount) / float64(total)

		if score == 1.0 {
			detail.ComplianceMessage = "Perfect compliance! Either very secure or very good at lying to auditors."
		} else if score >= 0.9 {
			detail.ComplianceMessage = "Excellent compliance. The auditors will love you."
		} else if score >= 0.8 {
			detail.ComplianceMessage = "Good compliance. A few issues, but who's counting?"
		} else if score >= 0.7 {
			detail.ComplianceMessage = "Decent compliance. Room for improvement, but not on fire."
		} else if score >= 0.5 {
			detail.ComplianceMessage = "Moderate compliance. Glass half full... of security vulnerabilities."
		} else if score > 0 {
			detail.ComplianceMessage = "Poor compliance. But hey, at least something works!"
		} else {
			detail.ComplianceMessage = "Critical non-compliance. This device is basically a honeypot."
		}
	}

	return detail
}

const unknownVersion = "Unknown"

// ExtractOSInfo extracts OS name and version from system_info check output.
func ExtractOSInfo(device *gitmdm.Device) (string, string) {
	// First try system_info check
	if osName, osVersion := extractFromSystemInfo(device); osName != unknownVersion {
		return osName, osVersion
	}

	// Fallback to uname check
	return extractFromUnameCheck(device)
}

// extractFromSystemInfo extracts OS info from system_info check results.
func extractFromSystemInfo(device *gitmdm.Device) (string, string) {
	systemInfo, exists := device.Checks["system_info"]
	if !exists || len(systemInfo.Outputs) == 0 {
		return unknownVersion, unknownVersion
	}

	output := strings.TrimSpace(systemInfo.Outputs[0].Stdout)

	// Try parsing different OS formats
	if osName, osVersion := parseMacOSOutput(output); osName != unknownVersion {
		return osName, osVersion
	}
	if osName, osVersion := parseLinuxOutput(output); osName != unknownVersion {
		return osName, osVersion
	}
	if osName, osVersion := parseFreeBSDOutput(output); osName != unknownVersion {
		return osName, osVersion
	}
	if osName, osVersion := parseWindowsOutput(output); osName != unknownVersion {
		return osName, osVersion
	}

	return unknownVersion, unknownVersion
}

// extractFromUnameCheck extracts basic OS info from uname check as fallback.
func extractFromUnameCheck(device *gitmdm.Device) (string, string) {
	unameCheck, exists := device.Checks["uname"]
	if !exists || len(unameCheck.Outputs) == 0 {
		return unknownVersion, unknownVersion
	}

	output := strings.TrimSpace(unameCheck.Outputs[0].Stdout)
	return parseUnameOutput(output)
}

// parseUnameOutput parses uname command output to extract OS name.
func parseUnameOutput(output string) (string, string) {
	if strings.HasPrefix(output, "Darwin") {
		return "macOS", unknownVersion
	}
	if strings.Contains(output, "Linux") {
		return "Linux", unknownVersion
	}
	if strings.Contains(output, "FreeBSD") {
		return "FreeBSD", unknownVersion
	}
	if strings.Contains(output, "Windows") {
		return "Windows", unknownVersion
	}

	// Extract first word as OS name
	parts := strings.Fields(output)
	if len(parts) > 0 {
		return parts[0], unknownVersion
	}

	return unknownVersion, unknownVersion
}

// parseMacOSOutput parses macOS sw_vers output.
func parseMacOSOutput(output string) (string, string) {
	if !strings.Contains(output, "ProductName") {
		return unknownVersion, unknownVersion
	}

	var productName, productVersion string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ProductName:") {
			productName = strings.TrimSpace(strings.TrimPrefix(line, "ProductName:"))
		} else if strings.HasPrefix(line, "ProductVersion:") {
			productVersion = strings.TrimSpace(strings.TrimPrefix(line, "ProductVersion:"))
		}
	}

	if productName != "" && productVersion != "" {
		return productName, productVersion
	}
	return unknownVersion, unknownVersion
}

// parseLinuxOutput parses Linux /etc/os-release output.
func parseLinuxOutput(output string) (string, string) {
	if !strings.Contains(output, "NAME=") {
		return unknownVersion, unknownVersion
	}

	var name, version string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), `"`)
		} else if strings.HasPrefix(line, "VERSION=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION="), `"`)
		} else if strings.HasPrefix(line, "VERSION_ID=") && version == "" {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}

	if name != "" {
		if version != "" {
			return name, version
		}
		return name, unknownVersion
	}
	return unknownVersion, unknownVersion
}

// parseFreeBSDOutput parses FreeBSD freebsd-version output.
func parseFreeBSDOutput(output string) (string, string) {
	if !strings.Contains(output, "FreeBSD") {
		return unknownVersion, unknownVersion
	}

	lines := strings.Split(output, "\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			return "FreeBSD", parts[1]
		}
	}
	return "FreeBSD", unknownVersion
}

// parseWindowsOutput parses Windows systeminfo output.
func parseWindowsOutput(output string) (string, string) {
	if !strings.Contains(output, "OS Name") {
		return unknownVersion, unknownVersion
	}

	var osName, osVersion string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "OS Name:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				osName = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "OS Version:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				osVersion = strings.TrimSpace(parts[1])
			}
		}
	}

	if osName != "" {
		if osVersion != "" {
			return osName, osVersion
		}
		return osName, unknownVersion
	}
	return unknownVersion, unknownVersion
}
