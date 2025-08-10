package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"time"
)

const (
	installDir = ".gitmdm"
	agentName  = "gitmdm-agent"
	configName = "config.json"
)

// AgentConfig stores the agent configuration.
type AgentConfig struct {
	ServerURL string `json:"server_url"`
	JoinKey   string `json:"join_key"`
}

// configDir returns the appropriate configuration directory for the platform.
// os.UserConfigDir() returns:
// - macOS: ~/Library/Application Support
// - Linux/BSD: $XDG_CONFIG_HOME or ~/.config
// - Windows: %AppData%.
func configDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config directory: %w", err)
	}
	return filepath.Join(configDir, "gitmdm"), nil
}

// loadConfig loads the agent configuration from the config file.
func loadConfig() (*AgentConfig, error) {
	configDir, err := configDir()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(configDir, configName)
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config AgentConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// installExecutable copies the executable to the target path, handling busy files.
func installExecutable(exePath, targetPath string) error {
	// Stop any existing instance (but not ourselves)
	// Note: We accept the TOCTOU risk here as it's a best-effort cleanup
	if _, err := os.Stat(targetPath); err == nil {
		// Use exec.Command directly to avoid shell injection
		// The targetPath is safe (constructed from constants) but better to be explicit
		cmd := exec.Command("pkill", "-f", targetPath) //nolint:noctx // killing existing process doesn't need context
		_ = cmd.Run()                                  //nolint:errcheck // Best effort
		time.Sleep(500 * time.Millisecond)
	}

	// Try direct copy first
	data, err := os.ReadFile(exePath)
	if err != nil {
		return fmt.Errorf("failed to read executable: %w", err)
	}
	if err := os.WriteFile(targetPath, data, 0o755); err != nil { //nolint:gosec // executable needs execute permission
		// Handle "text file busy" error by copying to temp and renaming
		if !strings.Contains(strings.ToLower(err.Error()), "text file busy") {
			return fmt.Errorf("failed to copy executable: %w", err)
		}

		// Copy to temp file and rename
		tempPath := targetPath + ".new"
		if err := os.WriteFile(tempPath, data, 0o755); err != nil { //nolint:gosec // executable needs execute permission
			return fmt.Errorf("failed to copy executable to temp file: %w", err)
		}
		if err := os.Rename(tempPath, targetPath); err != nil {
			_ = os.Remove(targetPath) //nolint:errcheck // Try removing old file
			if err := os.Rename(tempPath, targetPath); err != nil {
				return fmt.Errorf("failed to replace executable: %w", err)
			}
		}
	}
	return nil
}

// installAgent installs the agent to run automatically at system startup.
func installAgent(serverURL, joinKey string) error {
	// Get home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	// Create installation directory
	targetDir := filepath.Join(homeDir, installDir)
	if err := os.MkdirAll(targetDir, 0o755); err != nil { //nolint:gosec // standard directory permissions for program dir
		return fmt.Errorf("failed to create directory %s: %w", targetDir, err)
	}

	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Copy executable to installation directory
	targetPath := filepath.Join(targetDir, agentName)

	// Check if we're already running from the target location
	if exePath == targetPath {
		fmt.Printf("Agent is already installed at %s\n", targetPath)
		// Just need to ensure autostart is configured
	} else {
		if err := installExecutable(exePath, targetPath); err != nil {
			return err
		}
	}

	// Make executable
	if err := os.Chmod(targetPath, 0o755); err != nil { //nolint:gosec // executable needs execute permission
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	// Save configuration file to proper config directory with restricted permissions
	configDir, err := configDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configPath := filepath.Join(configDir, configName)
	config := AgentConfig{
		ServerURL: serverURL,
		JoinKey:   joinKey,
	}
	configData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	// Write config with 0600 permissions (readable only by owner)
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	// Install platform-specific autostart (without sensitive data in command line)
	switch runtime.GOOS {
	case "darwin":
		return installMacOS(targetPath, serverURL, joinKey)
	case "linux":
		return installLinux(targetPath, serverURL, joinKey)
	case "freebsd", "openbsd", "netbsd":
		return installCron(targetPath, serverURL, joinKey)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// uninstallAgent removes the agent and autostart configuration.
func uninstallAgent() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	targetDir := filepath.Join(homeDir, installDir)
	targetPath := filepath.Join(targetDir, agentName)

	// Remove platform-specific autostart
	switch runtime.GOOS {
	case "darwin":
		if err := uninstallMacOS(); err != nil {
			return err
		}
	case "linux":
		if err := uninstallLinux(); err != nil {
			return err
		}
	case "freebsd", "openbsd", "netbsd":
		if err := uninstallCron(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	// Remove executable
	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove executable: %w", err)
	}

	// Remove directory if empty
	_ = os.Remove(targetDir) //nolint:errcheck // Directory might not be empty, that's OK

	return nil
}

// isSystemdUserAvailable checks if systemd user services are available and working.
func isSystemdUserAvailable() bool {
	// Check if systemctl exists
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}

	// Check if systemd --user is running
	cmd := exec.Command("systemctl", "--user", "is-system-running") //nolint:noctx // local command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}

	// Valid statuses indicate systemd is running
	status := strings.TrimSpace(string(output))
	switch status {
	case "running", "degraded", "maintenance", "starting", "stopping":
		return true
	default:
		return false
	}
}

// installMacOS installs launchd plist for macOS.
func installMacOS(agentPath, serverURL, joinKey string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	plistPath := filepath.Join(homeDir, "Library", "LaunchAgents", "com.gitmdm.agent.plist")

	// Create LaunchAgents directory if it doesn't exist
	launchAgentsDir := filepath.Join(homeDir, "Library", "LaunchAgents")
	if err := os.MkdirAll(launchAgentsDir, 0o755); err != nil { //nolint:gosec // standard permissions for LaunchAgents
		return fmt.Errorf("failed to create LaunchAgents directory: %w", err)
	}

	plistContent := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.gitmdm.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.AgentPath}}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{{.HomeDir}}/Library/Logs/gitmdm-agent.log</string>
    <key>StandardErrorPath</key>
    <string>{{.HomeDir}}/Library/Logs/gitmdm-agent.error.log</string>
</dict>
</plist>
`

	tmpl, err := template.New("plist").Parse(plistContent)
	if err != nil {
		return fmt.Errorf("failed to parse plist template: %w", err)
	}

	file, err := os.Create(plistPath)
	if err != nil {
		return fmt.Errorf("failed to create plist file: %w", err)
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // defer close

	data := struct {
		AgentPath string
		ServerURL string
		JoinKey   string
		HomeDir   string
	}{
		AgentPath: agentPath,
		ServerURL: serverURL,
		JoinKey:   joinKey,
		HomeDir:   homeDir,
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to write plist: %w", err)
	}

	// Load the launch agent (this starts it immediately due to RunAtLoad=true)
	log.Printf("[INFO] Loading launch agent from %s", plistPath)
	cmd := exec.Command("launchctl", "load", plistPath) //nolint:noctx // local command
	if _, err := cmd.CombinedOutput(); err != nil {
		// Try to unload first in case it's already loaded
		log.Print("[INFO] Agent may already be loaded, attempting to unload first")
		_ = exec.Command("launchctl", "unload", plistPath).Run() //nolint:errcheck,noctx // Best effort
		// Try loading again
		cmd = exec.Command("launchctl", "load", plistPath) //nolint:noctx // local command
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to load launch agent: %w\nOutput: %s", err, output)
		}
	}
	log.Print("[INFO] Launch agent loaded successfully - agent should be running now")

	return nil
}

// uninstallMacOS removes launchd configuration.
func uninstallMacOS() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	plistPath := filepath.Join(homeDir, "Library", "LaunchAgents", "com.gitmdm.agent.plist")

	// Unload the launch agent
	_ = exec.Command("launchctl", "unload", plistPath).Run() //nolint:errcheck,noctx // Best effort

	// Remove plist file
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove plist: %w", err)
	}

	return nil
}

// installLinux installs systemd user service for Linux.
func installLinux(agentPath, serverURL, joinKey string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Check if systemd is available AND user services are working
	if !isSystemdUserAvailable() {
		// Fall back to cron
		fmt.Println("Systemd user services not available, using cron instead")
		return installCron(agentPath, serverURL, joinKey)
	}

	serviceDir := filepath.Join(homeDir, ".config", "systemd", "user")
	if err := os.MkdirAll(serviceDir, 0o755); err != nil { //nolint:gosec // standard permissions for systemd services
		return fmt.Errorf("failed to create systemd directory: %w", err)
	}

	servicePath := filepath.Join(serviceDir, "gitmdm-agent.service")

	serviceContent := `[Unit]
Description=GitMDM Compliance Agent
After=network.target

[Service]
Type=simple
ExecStart={{.AgentPath}}
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
`

	tmpl, err := template.New("service").Parse(serviceContent)
	if err != nil {
		return fmt.Errorf("failed to parse service template: %w", err)
	}

	file, err := os.Create(servicePath)
	if err != nil {
		return fmt.Errorf("failed to create service file: %w", err)
	}
	defer func() { _ = file.Close() }() //nolint:errcheck // defer close

	data := struct {
		AgentPath string
		ServerURL string
		JoinKey   string
	}{
		AgentPath: agentPath,
		ServerURL: serverURL,
		JoinKey:   joinKey,
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Reload systemd user daemon
	cmd := exec.Command("systemctl", "--user", "daemon-reload") //nolint:noctx // local command
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable service
	cmd = exec.Command("systemctl", "--user", "enable", "gitmdm-agent.service") //nolint:noctx // local command
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	// Start service
	log.Print("[INFO] Starting systemd service")
	cmd = exec.Command("systemctl", "--user", "start", "gitmdm-agent.service") //nolint:noctx // local command
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}
	log.Print("[INFO] Systemd service started successfully")

	return nil
}

// uninstallLinux removes systemd service or cron job.
func uninstallLinux() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Try systemd first if user services are available
	if isSystemdUserAvailable() {
		// Stop service
		_ = exec.Command("systemctl", "--user", "stop", "gitmdm-agent.service").Run() //nolint:errcheck,noctx // Best effort
		// Disable service
		_ = exec.Command("systemctl", "--user", "disable", "gitmdm-agent.service").Run() //nolint:errcheck,noctx // Best effort

		// Remove service file
		servicePath := filepath.Join(homeDir, ".config", "systemd", "user", "gitmdm-agent.service")
		if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove service file: %w", err)
		}

		// Reload systemd
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run() //nolint:errcheck,noctx // Best effort
	}

	// Also try to remove from cron
	_ = uninstallCron() //nolint:errcheck // Best effort

	return nil
}

const crontabCmd = "crontab"

// installCron installs a cron job (fallback for systems without systemd/launchd).
func installCron(agentPath, _, _ string) error {
	// Check if crontab is available
	if _, err := exec.LookPath(crontabCmd); err != nil {
		return errors.New("neither systemd user services nor cron are available - manual startup required")
	}

	// Get current crontab
	cmd := exec.Command(crontabCmd, "-l") //nolint:noctx // local command
	output, _ := cmd.Output()             //nolint:errcheck // Ignore error - no crontab is fine
	currentCron := string(output)

	// Check if already installed - look for the agent name in the crontab
	if strings.Contains(currentCron, agentName) {
		log.Printf("[INFO] Cron job for %s already installed, updating entries", agentName)
		// Remove old entries to replace with new ones
		var filteredLines []string
		for _, line := range strings.Split(currentCron, "\n") {
			if !strings.Contains(line, agentName) {
				filteredLines = append(filteredLines, line)
			}
		}
		currentCron = strings.Join(filteredLines, "\n")
	}

	// Add new cron jobs: run at reboot and every 15 minutes
	// The PID file mechanism in the agent prevents duplicate processes
	entries := []string{
		fmt.Sprintf("@reboot %s", agentPath),
		fmt.Sprintf("*/15 * * * * %s", agentPath), // Every 15 minutes
	}
	newCron := currentCron
	if !strings.HasSuffix(newCron, "\n") && newCron != "" {
		newCron += "\n"
	}
	for _, entry := range entries {
		newCron += entry + "\n"
	}

	// Install new crontab
	log.Printf("[INFO] Installing cron entries for %s", agentPath)
	cmd = exec.Command(crontabCmd, "-") //nolint:noctx // local command
	cmd.Stdin = strings.NewReader(newCron)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install crontab: %w", err)
	}
	log.Print("[INFO] Cron entries installed successfully")

	// Verify the crontab was actually installed
	cmd = exec.Command(crontabCmd, "-l") //nolint:noctx // local command
	if output, err := cmd.Output(); err == nil {
		if strings.Contains(string(output), agentPath) {
			log.Print("[INFO] Cron entries verified in crontab")
		} else {
			log.Print("[WARN] Cron entries not found in crontab after installation")
		}
	}

	// Try to start the agent immediately in background
	log.Printf("[INFO] Starting agent in background: %s", agentPath)

	// Check if nohup is available (it should be on all Unix-like systems including FreeBSD)
	nohupPath, err := exec.LookPath("nohup")
	if err != nil {
		log.Printf("[WARN] nohup not found, agent will start via cron in 15 minutes: %v", err)
		return nil
	}

	// Get the directory where the agent is installed
	agentDir := filepath.Dir(agentPath)

	// Start the agent directly with nohup, avoiding shell interpretation
	cmd = exec.Command(nohupPath, agentPath) //nolint:noctx // agent spawns its own context
	cmd.Dir = agentDir                       // Set working directory for PID file and logs

	// Redirect output to /dev/null
	devNull, err := os.Open("/dev/null")
	if err == nil {
		cmd.Stdout = devNull
		cmd.Stderr = devNull
		defer func() { _ = devNull.Close() }() //nolint:errcheck // defer close
	}

	if err := cmd.Start(); err != nil {
		log.Printf("[WARN] Failed to start agent with nohup: %v (will start via cron in 15 minutes)", err)
		return nil
	}

	// Detach from the process
	if err := cmd.Process.Release(); err != nil {
		log.Printf("[WARN] Failed to release process: %v", err)
	}

	log.Printf("[INFO] Agent started successfully in background using nohup (PID: %d)", cmd.Process.Pid)

	// Give it a moment to start
	time.Sleep(500 * time.Millisecond)
	// Verify the process is running
	checkCmd := exec.Command("pgrep", "-f", agentName) //nolint:noctx // local command
	if output, err := checkCmd.Output(); err == nil && len(output) > 0 {
		pids := strings.TrimSpace(string(output))
		log.Printf("[INFO] Agent process confirmed running with PID(s): %s", pids)
	} else {
		log.Print("[WARN] Could not confirm agent is running, but it may have started successfully")
	}

	return nil
}

// uninstallCron removes cron job.
func uninstallCron() error {
	// Get current crontab
	cmd := exec.Command(crontabCmd, "-l") //nolint:noctx // local command
	output, err := cmd.Output()
	if err != nil {
		return nil //nolint:nilerr // No crontab, nothing to remove
	}

	currentCron := string(output)

	// Remove gitmdm-agent entries
	var newLines []string
	for _, line := range strings.Split(currentCron, "\n") {
		if !strings.Contains(line, "gitmdm-agent") {
			newLines = append(newLines, line)
		}
	}

	newCron := strings.Join(newLines, "\n")

	// Install updated crontab
	if strings.TrimSpace(newCron) == "" {
		// Remove crontab entirely if empty
		_ = exec.Command(crontabCmd, "-r").Run() //nolint:errcheck,noctx // Best effort
	} else {
		cmd = exec.Command(crontabCmd, "-") //nolint:noctx // local command
		cmd.Stdin = strings.NewReader(newCron)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to update crontab: %w", err)
		}
	}

	// Try to stop any running agent
	_ = exec.Command("pkill", "-f", "gitmdm-agent").Run() //nolint:errcheck,noctx // Best effort

	return nil
}

// installWindows installs Windows Task Scheduler task.
//
//nolint:unused // Windows-specific function needed for cross-platform support
func installWindows(agentPath, _, _ string) error {
	// Create the task XML content
	taskXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>GitMDM Compliance Agent</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
    </Exec>
  </Actions>
</Task>`, agentPath)

	// Write task XML to temp file
	tempFile, err := os.CreateTemp("", "gitmdm-task-*.xml")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name()) //nolint:errcheck // best effort cleanup

	if _, err := tempFile.WriteString(taskXML); err != nil {
		return fmt.Errorf("failed to write task XML: %w", err)
	}
	_ = tempFile.Close() //nolint:errcheck // file already written

	// Delete existing task if present (ignore errors)
	cmd := exec.Command("schtasks", "/Delete", "/TN", "GitMDM Agent", "/F") //nolint:noctx // Windows task management doesn't need context
	_ = cmd.Run()                                                           //nolint:errcheck // best effort cleanup

	// Create the scheduled task
	//nolint:noctx,gosec,lll // Windows task management doesn't need context, XML file is trusted
	cmd = exec.Command("schtasks", "/Create", "/TN", "GitMDM Agent", "/XML", tempFile.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create scheduled task: %w\nOutput: %s", err, output)
	}

	// Start the task immediately
	cmd = exec.Command("schtasks", "/Run", "/TN", "GitMDM Agent") //nolint:noctx // Windows task management doesn't need context
	_ = cmd.Run()                                                 //nolint:errcheck // Best effort

	return nil
}

// uninstallWindows removes Windows Task Scheduler task.
//
//nolint:unused // Windows-specific function needed for cross-platform support
func uninstallWindows() error {
	// Stop the task
	cmd := exec.Command("schtasks", "/End", "/TN", "GitMDM Agent") //nolint:noctx // Windows task management doesn't need context
	_ = cmd.Run()                                                  //nolint:errcheck // Best effort

	// Delete the task
	cmd = exec.Command("schtasks", "/Delete", "/TN", "GitMDM Agent", "/F") //nolint:noctx // Windows task management doesn't need context
	output, err := cmd.CombinedOutput()
	if err != nil {
		if !strings.Contains(string(output), "The system cannot find") {
			return fmt.Errorf("failed to delete scheduled task: %w\nOutput: %s", err, output)
		}
		// Task doesn't exist, that's fine
	}

	// Try to stop any running agent process
	cmd = exec.Command("taskkill", "/F", "/IM", "gitmdm-agent.exe") //nolint:noctx // Windows process management doesn't need context
	_ = cmd.Run()                                                   //nolint:errcheck // Best effort

	return nil
}
