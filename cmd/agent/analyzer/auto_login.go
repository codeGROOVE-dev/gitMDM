package analyzer

import "strings"

const (
	statusPass = "pass"
	statusFail = "fail"
	statusNA   = "n/a"

	minOutputLength = 10
)

// analyzeAutoLogin checks if automatic login is configured on the system.
func analyzeAutoLogin(output string, osName string, baseCommand string) Result {
	if osName == "darwin" && baseCommand == "defaults" {
		return analyzeMacOSAutoLogin(output)
	}

	// Check various Linux display managers
	if result := analyzeGDMAutoLogin(output); result.Status != statusNA {
		return result
	}
	if result := analyzeLightDMAutoLogin(output); result.Status != statusNA {
		return result
	}
	if result := analyzeSDDMAutoLogin(output); result.Status != statusNA {
		return result
	}
	if result := analyzeGettyAutoLogin(output); result.Status != statusNA {
		return result
	}

	return analyzeGenericAutoLogin(output)
}

// analyzeMacOSAutoLogin checks macOS automatic login settings.
func analyzeMacOSAutoLogin(output string) Result {
	if strings.Contains(output, "autologinuser") {
		if isErrorOutput(output) || strings.TrimSpace(output) == "" {
			if strings.Contains(output, "does not exist") {
				return Result{Status: statusPass, Description: "Automatic login disabled"}
			}
			return Result{Status: statusNA, Description: "Unable to determine auto login status"}
		}

		username := strings.TrimSpace(output)
		if username != "" && username != "0" {
			return Result{
				Status:      statusFail,
				Description: "Automatic login enabled for user: " + username,
				Remediation: getMacOSAutoLoginRemediation(),
			}
		}
	}

	if strings.Contains(output, "autologinuseruid") && !isErrorOutput(output) {
		uid := strings.TrimSpace(output)
		if uid != "" && uid != "0" {
			return Result{
				Status:      statusFail,
				Description: "Automatic login enabled (UID: " + uid + ")",
				Remediation: getMacOSAutoLoginRemediation(),
			}
		}
	}

	return Result{Status: statusNA, Description: "Unable to determine auto login status"}
}

// analyzeGDMAutoLogin checks GDM/GDM3 automatic login configuration.
func analyzeGDMAutoLogin(output string) Result {
	if !strings.Contains(output, "[daemon]") && !strings.Contains(output, "gdm") {
		return Result{Status: statusNA, Description: "Not GDM output"}
	}

	// Determine GDM config file location
	configFile := "/etc/gdm3/custom.conf"
	if strings.Contains(output, "/etc/gdm/") {
		configFile = "/etc/gdm/custom.conf"
	}

	if strings.Contains(output, "automaticloginenable") {
		if strings.Contains(output, "automaticloginenable=true") ||
			strings.Contains(output, "automaticloginenable = true") {
			return Result{
				Status:      statusFail,
				Description: "GDM automatic login enabled",
				Remediation: getGDMRemediation(configFile),
			}
		}
		if strings.Contains(output, "automaticloginenable=false") ||
			strings.Contains(output, "automaticloginenable = false") {
			return Result{Status: statusPass, Description: "GDM automatic login disabled"}
		}
	}

	if user := extractGDMAutoLoginUser(output); user != "" {
		return Result{
			Status:      statusFail,
			Description: "GDM automatic login enabled for: " + user,
			Remediation: getGDMUserRemediation(configFile, user),
		}
	}

	return Result{Status: statusNA, Description: "Not GDM output"}
}

// analyzeLightDMAutoLogin checks LightDM automatic login configuration.
func analyzeLightDMAutoLogin(output string) Result {
	if !strings.Contains(output, "lightdm") && !strings.Contains(output, "[seatdefaults]") {
		return Result{Status: statusNA, Description: "Not LightDM output"}
	}

	if user := extractLightDMAutoLoginUser(output); user != "" {
		return Result{
			Status:      statusFail,
			Description: "LightDM automatic login enabled for: " + user,
			Remediation: []string{
				"Edit /etc/lightdm/lightdm.conf",
				"Remove or comment out 'autologin-user=" + user + "'",
				"Restart LightDM: sudo systemctl restart lightdm",
			},
		}
	}

	return Result{Status: statusNA, Description: "Not LightDM output"}
}

// analyzeSDDMAutoLogin checks SDDM automatic login configuration.
func analyzeSDDMAutoLogin(output string) Result {
	if !strings.Contains(output, "sddm") && !strings.Contains(output, "[autologin]") {
		return Result{Status: statusNA, Description: "Not SDDM output"}
	}

	if user := extractSDDMAutoLoginUser(output); user != "" {
		return Result{
			Status:      statusFail,
			Description: "SDDM automatic login enabled for: " + user,
			Remediation: []string{
				"Edit /etc/sddm.conf",
				"Remove the [Autologin] section or set User= to empty",
				"Restart SDDM: sudo systemctl restart sddm",
			},
		}
	}

	return Result{Status: statusNA, Description: "Not SDDM output"}
}

// analyzeGettyAutoLogin checks systemd getty automatic login configuration.
func analyzeGettyAutoLogin(output string) Result {
	if !strings.Contains(output, "getty") || !strings.Contains(output, "autologin") {
		return Result{Status: statusNA, Description: "Not getty output"}
	}

	if user := extractGettyAutoLoginUser(output); user != "" {
		return Result{
			Status:      statusFail,
			Description: "TTY automatic login enabled for: " + user,
			Remediation: []string{
				"Remove or rename the auto-login configuration file",
				"sudo rm /etc/systemd/system/getty@tty1.service.d/autologin.conf",
				"Reload systemd: sudo systemctl daemon-reload",
				"Restart getty: sudo systemctl restart getty@tty1",
			},
		}
	}

	return Result{Status: statusNA, Description: "Not getty output"}
}

// analyzeGenericAutoLogin handles generic output analysis.
func analyzeGenericAutoLogin(output string) Result {
	if strings.Contains(output, "no such file") ||
		strings.Contains(output, "not found") ||
		strings.Contains(output, "permission denied") ||
		strings.Contains(output, "cannot open") {
		return Result{Status: statusPass, Description: "Automatic login not configured"}
	}

	if len(output) > minOutputLength {
		return Result{Status: statusPass, Description: "Automatic login disabled"}
	}

	return Result{Status: statusNA, Description: "Unable to determine auto login status"}
}

// Helper functions

func isErrorOutput(output string) bool {
	return strings.Contains(output, "does not exist") || strings.Contains(output, "error")
}

func extractGDMAutoLoginUser(output string) string {
	if !strings.Contains(output, "automaticlogin=") {
		return ""
	}
	parts := strings.Split(output, "automaticlogin=")
	if len(parts) > 1 {
		return strings.TrimSpace(strings.Split(parts[1], "\n")[0])
	}
	return ""
}

func extractLightDMAutoLoginUser(output string) string {
	if !strings.Contains(output, "autologin-user=") || strings.Contains(output, "#autologin-user") {
		return ""
	}
	parts := strings.Split(output, "autologin-user=")
	if len(parts) > 1 {
		return strings.TrimSpace(strings.Split(parts[1], "\n")[0])
	}
	return ""
}

func extractSDDMAutoLoginUser(output string) string {
	if !strings.Contains(output, "user=") || !strings.Contains(output, "[autologin]") {
		return ""
	}

	lines := strings.Split(output, "\n")
	inAutoLogin := false
	for _, line := range lines {
		line = strings.TrimSpace(strings.ToLower(line))
		if line == "[autologin]" {
			inAutoLogin = true
			continue
		}
		if inAutoLogin && strings.HasPrefix(line, "[") {
			inAutoLogin = false
			continue
		}
		if inAutoLogin && strings.HasPrefix(line, "user=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "user="))
		}
	}
	return ""
}

func extractGettyAutoLoginUser(output string) string {
	if !strings.Contains(output, "--autologin") {
		return ""
	}
	parts := strings.Split(output, "--autologin")
	if len(parts) > 1 {
		userPart := strings.TrimSpace(parts[1])
		fields := strings.Fields(userPart)
		if len(fields) > 0 {
			return fields[0]
		}
	}
	return ""
}

func getMacOSAutoLoginRemediation() []string {
	return []string{
		"Open System Settings > Users & Groups",
		"Click the lock to make changes",
		"Click 'Login Options'",
		"Set 'Automatic login' to 'Off'",
		"Or use: sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser",
	}
}

func getGDMRemediation(configFile string) []string {
	serviceName := "gdm"
	if strings.Contains(configFile, "gdm3") {
		serviceName = "gdm3"
	}
	return []string{
		"Edit " + configFile,
		"Remove or comment out 'AutomaticLoginEnable=true'",
		"Remove or comment out 'AutomaticLogin=username'",
		"Restart GDM: sudo systemctl restart " + serviceName,
	}
}

func getGDMUserRemediation(configFile, user string) []string {
	serviceName := "gdm"
	if strings.Contains(configFile, "gdm3") {
		serviceName = "gdm3"
	}
	return []string{
		"Edit " + configFile,
		"Remove or comment out 'AutomaticLogin=" + user + "'",
		"Remove or comment out 'AutomaticLoginEnable=true'",
		"Restart GDM: sudo systemctl restart " + serviceName,
	}
}
