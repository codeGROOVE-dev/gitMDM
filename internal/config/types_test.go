package config_test

import (
	"gitmdm/internal/config"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseChecksYAML(t *testing.T) {
	// Load the actual checks.yaml file
	data, err := os.ReadFile("../../cmd/agent/checks.yaml")
	if err != nil {
		t.Fatalf("Failed to read checks.yaml: %v", err)
	}

	// Try to parse it
	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("Failed to parse checks.yaml: %v", err)
	}

	// Validate we got some checks
	if len(cfg.Checks) == 0 {
		t.Fatal("No checks were parsed from checks.yaml")
	}

	// Validate some expected checks exist
	expectedChecks := []string{"hostname", "firewall", "disk_encryption"}
	for _, name := range expectedChecks {
		if _, exists := cfg.Checks[name]; !exists {
			t.Errorf("Expected check '%s' not found in parsed config", name)
		}
	}

	// Test that we can get commands for different OSes
	if check, exists := cfg.Checks["disk_encryption"]; exists {
		// Debug: see what's in the map
		if linuxVal, ok := check["linux"]; ok {
			t.Logf("linux key exists, type: %T", linuxVal)
		} else {
			t.Log("linux key does not exist")
		}

		// Check that Linux has commands
		linuxCmds := check.CommandsForOS("linux")
		freebsdCmds := check.CommandsForOS("freebsd")

		if len(linuxCmds) == 0 {
			t.Error("No Linux commands found for disk_encryption")
		}
		if len(freebsdCmds) == 0 {
			t.Error("No FreeBSD commands found for disk_encryption")
		}
	}

	// Test a simple check
	if check, exists := cfg.Checks["hostname"]; exists {
		allCmds := check.CommandsForOS("darwin") // Should fall back to "all"
		if len(allCmds) == 0 {
			t.Error("No commands found for hostname check on darwin")
		}
	}

	t.Logf("Successfully parsed %d checks from checks.yaml", len(cfg.Checks))
}
