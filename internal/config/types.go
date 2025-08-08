// Package config defines configuration structures for gitMDM checks.
package config

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the complete checks configuration.
type Config struct {
	Checks map[string]CheckDefinition `yaml:"checks"`
}

// CheckDefinition defines how a check should be performed across different platforms.
// Field names follow Go build tag conventions.
type CheckDefinition struct {
	additionalRules map[string][]CommandRule
	Description     string        `yaml:"description,omitempty"`
	FreeBSD         []CommandRule `yaml:"freebsd,omitempty"`
	Darwin          []CommandRule `yaml:"darwin,omitempty"`
	Linux           []CommandRule `yaml:"linux,omitempty"`
	Windows         []CommandRule `yaml:"windows,omitempty"`
	Unix            []CommandRule `yaml:"unix,omitempty"`
	OpenBSD         []CommandRule `yaml:"openbsd,omitempty"`
	NetBSD          []CommandRule `yaml:"netbsd,omitempty"`
	Dragonfly       []CommandRule `yaml:"dragonfly,omitempty"`
	Solaris         []CommandRule `yaml:"solaris,omitempty"`
	Illumos         []CommandRule `yaml:"illumos,omitempty"`
	All             []CommandRule `yaml:"all,omitempty"`
}

// UnmarshalYAML implements custom YAML unmarshaling to support comma-separated OS keys.
func (cd *CheckDefinition) UnmarshalYAML(node *yaml.Node) error {
	// Create a temporary type to avoid recursion
	type checkDefAlias CheckDefinition

	// First unmarshal into a map to handle dynamic keys
	var raw map[string]any
	if err := node.Decode(&raw); err != nil {
		return err
	}

	// Initialize the additional rules map
	cd.additionalRules = make(map[string][]CommandRule)

	// Process each key-value pair
	for key, value := range raw {
		// Check if the key contains a comma (multi-OS specification)
		if !strings.Contains(key, ",") {
			continue
		}

		// Parse the command rules for this multi-OS key
		yamlBytes, err := yaml.Marshal(value)
		if err != nil {
			continue
		}
		var rules []CommandRule
		if err := yaml.Unmarshal(yamlBytes, &rules); err != nil {
			continue
		}

		// Split the key and store rules for each OS
		osNames := strings.Split(key, ",")
		for _, osName := range osNames {
			osName = strings.TrimSpace(osName)
			cd.additionalRules[osName] = rules
		}

		// Remove from raw map so it doesn't interfere with standard unmarshaling
		delete(raw, key)
	}

	// Marshal the cleaned map back to YAML and unmarshal into the struct
	cleanedYAML, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(cleanedYAML, (*checkDefAlias)(cd))
}

// CommandRule defines a single command or file check with evaluation criteria.
type CommandRule struct {
	// Check type - either output (command) or file
	Output string `yaml:"output,omitempty"` // Command to execute
	File   string `yaml:"file,omitempty"`   // File to read

	// Evaluation criteria (all are optional)
	Includes string `yaml:"includes,omitempty"` // Regex - fail if matches
	Excludes string `yaml:"excludes,omitempty"` // Regex - fail if doesn't match
	ExitCode *int   `yaml:"exitcode,omitempty"` // Fail if exit code matches

	// Remediation steps specific to this rule
	Remediation []string `yaml:"remediation,omitempty"`
}

// CommandsForOS returns the commands for a specific OS, handling inheritance.
// Priority order (similar to Go build tags):
// 1. Exact OS match (e.g., "freebsd")
// 2. Unix (for all Unix-like systems)
// 3. All (works on any OS).

// CommandsForOS returns the command rules for a specific OS.
func (cd *CheckDefinition) CommandsForOS(osName string) []CommandRule {
	// First check if there are rules from comma-separated OS specifications
	if cd.additionalRules != nil {
		if rules, exists := cd.additionalRules[osName]; exists && len(rules) > 0 {
			return rules
		}
	}

	// Check exact OS match
	switch osName {
	case "darwin":
		if len(cd.Darwin) > 0 {
			return cd.Darwin
		}
	case "linux":
		if len(cd.Linux) > 0 {
			return cd.Linux
		}
	case "windows":
		if len(cd.Windows) > 0 {
			return cd.Windows
		}
	case "freebsd":
		if len(cd.FreeBSD) > 0 {
			return cd.FreeBSD
		}
	case "openbsd":
		if len(cd.OpenBSD) > 0 {
			return cd.OpenBSD
		}
	case "netbsd":
		if len(cd.NetBSD) > 0 {
			return cd.NetBSD
		}
	case "dragonfly":
		if len(cd.Dragonfly) > 0 {
			return cd.Dragonfly
		}
	case "solaris":
		if len(cd.Solaris) > 0 {
			return cd.Solaris
		}
	case "illumos":
		// Check illumos first, then fall back to solaris
		if len(cd.Illumos) > 0 {
			return cd.Illumos
		}
		if len(cd.Solaris) > 0 {
			return cd.Solaris
		}
	default:
		// Unknown OS - will fall through to unix/all checks
	}

	// Check unix for Unix-like systems (all except Windows)
	if osName != "windows" && len(cd.Unix) > 0 {
		return cd.Unix
	}

	// Fall back to "all"
	return cd.All
}
