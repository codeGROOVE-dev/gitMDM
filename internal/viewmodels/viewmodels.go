// Package viewmodels provides view models for the web UI templates.
package viewmodels

import (
	"gitmdm/internal/gitmdm"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	excellentThreshold = 0.9
	veryGoodThreshold  = 0.8
	goodThreshold      = 0.7
	fairThreshold      = 0.5

	// Uptime regex capture group indices.
	uptimeMinutesIndex = 4
)

// DeviceListItem represents a device in the list view with compliance summary.
type DeviceListItem struct {
	LastSeen        time.Time
	HardwareID      string
	Hostname        string
	User            string
	OS              string
	Version         string
	ComplianceEmoji string
	ComplianceClass string
	ComplianceScore float64
	PassCount       int
	FailCount       int
	NACount         int
}

// DeviceListView represents the device list page view model with filters.
type DeviceListView struct {
	Search      string
	Status      string
	Devices     []DeviceListItem
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
	ComplianceMessage string
	FormattedUptime   string
	SortedChecks      []string
	FailingChecks     []string
	PassingChecks     []string
	NAChecks          []string
	PassCount         int
	FailCount         int
	NACount           int
}

// CheckResult represents the display info for a check.
type CheckResult struct {
	Status      string
	Reason      string
	Emoji       string
	Remediation []string
}

// parseUptimeValues extracts days, hours, and minutes from regex matches.
func parseUptimeValues(matches []string) (days, hours, mins int) {
	if len(matches) == 0 {
		return 0, 0, 0
	}

	if matches[1] != "" {
		if val, err := strconv.Atoi(matches[1]); err == nil {
			days = val
		}
	}
	if matches[2] != "" {
		if val, err := strconv.Atoi(matches[2]); err == nil {
			hours = val
		}
	}
	if matches[3] != "" {
		if val, err := strconv.Atoi(matches[3]); err == nil {
			mins = val
		}
	}
	if len(matches) > uptimeMinutesIndex && matches[uptimeMinutesIndex] != "" {
		if val, err := strconv.Atoi(matches[uptimeMinutesIndex]); err == nil {
			mins = val
		}
	}
	return days, hours, mins
}

// formatUptimeDuration formats the parsed uptime values.
func formatUptimeDuration(days, hours, mins int) string {
	switch {
	case days > 0:
		if days == 1 {
			return "1 day"
		}
		return strconv.Itoa(days) + " days"
	case hours > 0:
		if hours == 1 {
			return "1 hour"
		}
		return strconv.Itoa(hours) + " hours"
	case mins > 0:
		if mins == 1 {
			return "1 minute"
		}
		return strconv.Itoa(mins) + " minutes"
	default:
		return "less than 1 minute"
	}
}

// formatUptime parses various uptime formats and returns a human-readable string.
func formatUptime(uptime string) string {
	if uptime == "" || uptime == "unavailable" || uptime == "unsupported" {
		return uptime
	}

	// Try to parse macOS/Linux uptime format (e.g., "17:05  up 35 mins, 3 users, load averages: 2.68 2.93 2.87")
	uptimeRegex := regexp.MustCompile(`up\s+(?:(\d+)\s+days?,\s*)?(?:(\d+):(\d+),|(\d+)\s+mins?)`)
	matches := uptimeRegex.FindStringSubmatch(uptime)

	if len(matches) > 0 {
		days, hours, mins := parseUptimeValues(matches)
		return formatUptimeDuration(days, hours, mins)
	}

	// Try to parse Windows format or if the regex didn't match, return the original
	return uptime
}

// BuildDeviceDetail creates a detailed view model for a single device.
// staleThreshold determines which checks to include - zero time means include all.
func BuildDeviceDetail(device *gitmdm.Device, staleThreshold time.Time) *DeviceDetail {
	detail := &DeviceDetail{
		Device:          device,
		CheckResults:    make(map[string]CheckResult),
		FormattedUptime: formatUptime(device.SystemUptime),
	}

	// Process all checks
	for checkName, check := range device.Checks {
		// Skip stale checks only if we have a threshold and the check has a timestamp
		if !staleThreshold.IsZero() && !check.Timestamp.IsZero() && check.Timestamp.Before(staleThreshold) {
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

		switch {
		case score == 1.0:
			detail.ComplianceMessage = "Perfect compliance! Either very secure or very good at lying to auditors."
		case score >= excellentThreshold:
			detail.ComplianceMessage = "Excellent compliance. The auditors will love you."
		case score >= veryGoodThreshold:
			detail.ComplianceMessage = "Good compliance. A few issues, but who's counting?"
		case score >= goodThreshold:
			detail.ComplianceMessage = "Decent compliance. Room for improvement, but not on fire."
		case score >= fairThreshold:
			detail.ComplianceMessage = "Moderate compliance. Glass half full... of security vulnerabilities."
		case score > 0:
			detail.ComplianceMessage = "Poor compliance. But hey, at least something works!"
		default:
			detail.ComplianceMessage = "Critical non-compliance. This device is basically a honeypot."
		}
	}

	return detail
}

const unknownVersion = "Unknown"

// ExtractOSInfo extracts OS name and version from system_info check output.
func ExtractOSInfo(device *gitmdm.Device) (osName, version string) {
	// First try system_info check
	if osName, osVersion := extractFromSystemInfo(device); osName != unknownVersion {
		return osName, osVersion
	}

	// Fallback to uname check
	return extractFromUnameCheck(device)
}

// extractFromSystemInfo extracts OS info from system_info check results.
func extractFromSystemInfo(device *gitmdm.Device) (osName, version string) {
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
	if osName, osVersion := parseUnixUnameOutput(output); osName != unknownVersion {
		return osName, osVersion
	}
	if osName, osVersion := parseWindowsOutput(output); osName != unknownVersion {
		return osName, osVersion
	}

	return unknownVersion, unknownVersion
}

// extractFromUnameCheck extracts basic OS info from uname check as fallback.
func extractFromUnameCheck(device *gitmdm.Device) (osName, version string) {
	unameCheck, exists := device.Checks["uname"]
	if !exists || len(unameCheck.Outputs) == 0 {
		return unknownVersion, unknownVersion
	}

	output := strings.TrimSpace(unameCheck.Outputs[0].Stdout)
	return parseUnameOutput(output)
}

// parseUnameOutput parses uname command output to extract OS name.
func parseUnameOutput(output string) (osName, version string) {
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
func parseMacOSOutput(output string) (osName, version string) {
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
func parseLinuxOutput(output string) (osName, version string) {
	if !strings.Contains(output, "NAME=") {
		return unknownVersion, unknownVersion
	}

	var name, versionStr string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "NAME="):
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), `"`)
		case strings.HasPrefix(line, "VERSION="):
			versionStr = strings.Trim(strings.TrimPrefix(line, "VERSION="), `"`)
		case strings.HasPrefix(line, "VERSION_ID=") && versionStr == "":
			versionStr = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		default:
			// No action needed for other lines
		}
	}

	if name != "" {
		if versionStr != "" {
			return name, versionStr
		}
		return name, unknownVersion
	}
	return unknownVersion, unknownVersion
}

// parseUnixUnameOutput parses uname -srm output for Unix systems.
// Example outputs:
// OpenBSD 7.4 amd64
// FreeBSD 14.0-RELEASE amd64
// NetBSD 10.0 amd64
// DragonFly 6.4-RELEASE x86_64.
func parseUnixUnameOutput(output string) (osName, version string) {
	parts := strings.Fields(output)
	if len(parts) < 2 {
		return unknownVersion, unknownVersion
	}

	// First field is OS name, second is version
	osName = parts[0]
	version = parts[1]

	// Clean up version strings that have -RELEASE, -CURRENT, etc.
	if idx := strings.Index(version, "-"); idx > 0 {
		version = version[:idx]
	}

	return osName, version
}

// parseWindowsOutput parses Windows systeminfo output.
func parseWindowsOutput(output string) (osName, version string) {
	if !strings.Contains(output, "OS Name") {
		return unknownVersion, unknownVersion
	}

	var osNameStr, osVersion string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "OS Name:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				osNameStr = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "OS Version:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				osVersion = strings.TrimSpace(parts[1])
			}
		}
	}

	if osNameStr != "" {
		if osVersion != "" {
			return osNameStr, osVersion
		}
		return osNameStr, unknownVersion
	}
	return unknownVersion, unknownVersion
}
