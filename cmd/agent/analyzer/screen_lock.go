package analyzer

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	maxComplianceSeconds = 900 // 15 minutes for SOC 2 compliance
)

// extractNumber tries to extract a number from a string
func extractNumber(s string) int {
	// Try to parse the whole string as a number first
	if num, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return num
	}

	// If that doesn't work, look for a number in the string
	// This handles cases like "askForPasswordDelay = 14400"
	parts := strings.Fields(s)
	for _, part := range parts {
		if num, err := strconv.Atoi(part); err == nil {
			return num
		}
	}

	return -1
}

// analyzeScreenLock checks screen lock configuration across different platforms and desktop environments.
func analyzeScreenLock(output string, osName string, baseCommand string, command string) Result {
	switch baseCommand {
	case "gsettings":
		return analyzeGNOMEScreenLock(output)
	case "xset":
		return analyzeX11ScreenSaver(output)
	case "defaults":
		if osName == "darwin" {
			return analyzeMacOSDefaults(output, command)
		}
	case "sysadminctl":
		return analyzeMacOSSysadminctl(output)
	}

	return analyzeGenericScreenLock(output)
}

// analyzeGNOMEScreenLock checks GNOME desktop screen lock settings.
func analyzeGNOMEScreenLock(output string) Result {
	if strings.Contains(output, "true") {
		return Result{Status: statusPass, Description: "GNOME screen lock enabled"}
	}
	if strings.Contains(output, "false") {
		return Result{Status: statusFail, Description: "GNOME screen lock disabled"}
	}
	return Result{Status: statusNA, Description: "Unable to determine GNOME screen lock status"}
}

// analyzeX11ScreenSaver checks X11 screen saver timeout configuration.
func analyzeX11ScreenSaver(output string) Result {
	if strings.Contains(output, "timeout") && !strings.Contains(output, "timeout:  0") {
		return Result{Status: statusPass, Description: "X11 screen timeout configured"}
	}
	if strings.Contains(output, "timeout:  0") {
		return Result{Status: statusFail, Description: "X11 screen timeout disabled"}
	}
	return Result{Status: statusNA, Description: "Unable to determine X11 screen saver status"}
}

// analyzeMacOSDefaults checks macOS defaults screen lock settings.
func analyzeMacOSDefaults(output, command string) Result {
	if strings.Contains(command, "idleTime") || strings.Contains(strings.ToLower(output), "idletime") {
		return analyzeMacOSIdleTime(output)
	}
	if strings.Contains(strings.ToLower(output), "askforpassworddelay") {
		return analyzeMacOSPasswordDelay(output)
	}
	return analyzeMacOSAskForPassword(output)
}

// analyzeMacOSIdleTime checks macOS screensaver idle time settings.
func analyzeMacOSIdleTime(output string) Result {
	num := extractNumber(output)
	if num == -1 {
		return Result{Status: statusFail, Description: "Screen idle time not configured (default 20 min, SOC 2 requires ≤15 min)"}
	}
	if num == 0 {
		return Result{Status: statusNA, Description: "Screen idle time disabled (0)"}
	}
	if num > maxComplianceSeconds {
		return createTimeoutFailResult(num, "Screen idle time too long", getMacOSIdleTimeRemediation())
	}
	return createTimePassResult(num, "Screen idle time compliant")
}

// analyzeMacOSPasswordDelay checks macOS password delay settings.
func analyzeMacOSPasswordDelay(output string) Result {
	num := extractNumber(output)
	if num == -1 {
		return Result{Status: statusPass, Description: "Password delay immediate (default)"}
	}
	if num == 0 {
		return Result{Status: statusPass, Description: "Password delay immediate"}
	}
	if num > maxComplianceSeconds {
		return createTimeoutFailResult(num, "Password delay too long", getMacOSPasswordDelayRemediation())
	}
	return createTimePassResult(num, "Password delay compliant")
}

// analyzeMacOSAskForPassword checks macOS ask for password setting.
func analyzeMacOSAskForPassword(output string) Result {
	if strings.Contains(output, "1") || strings.Contains(output, "true") {
		return Result{Status: statusPass, Description: "Password on wake enabled"}
	}
	if strings.Contains(output, "0") || strings.Contains(output, "false") {
		return Result{Status: statusFail, Description: "Password on wake disabled"}
	}
	return Result{Status: statusNA, Description: "Unable to determine password on wake setting"}
}

// analyzeMacOSSysadminctl checks macOS sysadminctl screen lock status.
func analyzeMacOSSysadminctl(output string) Result {
	if strings.Contains(output, "screenlock delay") {
		return analyzeSysadminctlDelay(output)
	}
	if strings.Contains(output, "screenlock is on") {
		return Result{Status: statusPass, Description: "macOS screen lock enabled"}
	}
	if strings.Contains(output, "screenlock is off") {
		return Result{Status: statusFail, Description: "macOS screen lock disabled"}
	}
	return Result{Status: statusNA, Description: "Unable to determine macOS screen lock status"}
}

// analyzeSysadminctlDelay extracts and validates screen lock delay from sysadminctl output.
func analyzeSysadminctlDelay(output string) Result {
	parts := strings.Fields(output)
	for i, part := range parts {
		if part == "delay" && i+2 < len(parts) && parts[i+1] == "is" {
			if num, err := strconv.Atoi(parts[i+2]); err == nil {
				if num == 0 {
					return Result{Status: statusPass, Description: "Screen lock delay immediate"}
				}
				if num > maxComplianceSeconds {
					return createTimeoutFailResult(num, "Screen lock delay too long", getMacOSPasswordDelayRemediation())
				}
				return createTimePassResult(num, "Screen lock delay compliant")
			}
		}
	}
	return Result{Status: statusNA, Description: "Unable to parse screen lock delay"}
}

// analyzeGenericScreenLock performs generic screen lock analysis.
func analyzeGenericScreenLock(output string) Result {
	enabled := isScreenLockEnabled(output)
	disabled := isScreenLockDisabled(output)

	if enabled && !disabled {
		return Result{Status: statusPass, Description: "Screen lock enabled"}
	}
	if disabled && !enabled {
		return Result{Status: statusFail, Description: "Screen lock disabled"}
	}
	if isUndeterminableOutput(output) {
		return Result{Status: statusNA, Description: "Screen lock status unknown"}
	}
	return Result{Status: statusFail, Description: "Screen lock not properly configured"}
}

// isScreenLockEnabled checks if output indicates screen lock is enabled.
func isScreenLockEnabled(output string) bool {
	return strings.Contains(output, "true") ||
		strings.Contains(output, "1") ||
		strings.Contains(output, "enabled") ||
		strings.Contains(output, "yes") ||
		strings.Contains(output, "timeout")
}

// isScreenLockDisabled checks if output indicates screen lock is disabled.
func isScreenLockDisabled(output string) bool {
	return strings.Contains(output, "false") ||
		(strings.Contains(output, "0") && !strings.Contains(output, "delay = 0")) ||
		strings.Contains(output, "disabled") ||
		strings.Contains(output, "never")
}

// isUndeterminableOutput checks if output indicates we cannot determine status.
func isUndeterminableOutput(output string) bool {
	return strings.Contains(output, "not found") ||
		strings.Contains(output, "permission denied") ||
		len(output) < minOutputLength
}

// createTimeoutFailResult creates a failure result for timeout values that are too long.
func createTimeoutFailResult(seconds int, description string, remediation []string) Result {
	minutes := seconds / 60
	hours := minutes / 60

	if hours > 0 {
		pluralS := ""
		if hours != 1 {
			pluralS = "s"
		}
		return Result{
			Status:      statusFail,
			Description: fmt.Sprintf("%s (%d hour%s, SOC 2 requires ≤15 min)", description, hours, pluralS),
			Remediation: remediation,
		}
	}
	return Result{
		Status:      statusFail,
		Description: fmt.Sprintf("%s (%d minutes, SOC 2 requires ≤15 min)", description, minutes),
		Remediation: remediation,
	}
}

// createTimePassResult creates a pass result for compliant timeout values.
func createTimePassResult(seconds int, description string) Result {
	minutes := seconds / 60
	if minutes > 0 {
		return Result{Status: statusPass, Description: fmt.Sprintf("%s (%d minutes)", description, minutes)}
	}
	return Result{Status: statusPass, Description: fmt.Sprintf("%s (%d seconds)", description, seconds)}
}

// getMacOSIdleTimeRemediation returns remediation steps for macOS idle time issues.
func getMacOSIdleTimeRemediation() []string {
	return []string{
		"Open System Settings > Lock Screen",
		"Set 'Start Screen Saver when inactive' to 15 minutes or less",
		"Or use: defaults -currentHost write com.apple.screensaver idleTime -int 900",
	}
}

// getMacOSPasswordDelayRemediation returns remediation steps for macOS password delay issues.
func getMacOSPasswordDelayRemediation() []string {
	return []string{
		"Open System Settings > Lock Screen",
		"Set 'Require password after screen saver begins' to 'immediately'",
		"Or use: defaults write com.apple.screensaver askForPasswordDelay -int 0",
	}
}
