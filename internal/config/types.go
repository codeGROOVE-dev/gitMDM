// Package config defines configuration structures for gitMDM checks.
package config

import (
	"strings"
)

// Config represents the complete checks configuration.
type Config struct {
	Checks map[string]CheckDefinition `yaml:"checks"`
}

// CheckDefinition is just a map of OS names to command rules.
// The key can be:
// - "description" for the check description
// - An OS name like "linux", "darwin", "windows"
// - A comma-separated list like "linux,freebsd"
// - "unix" for all Unix-like systems
// - "all" for all systems.
type CheckDefinition map[string]any

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

// CommandsForOS returns the command rules for a specific OS.
// Priority order:
// 1. Exact OS match (e.g., "freebsd")
// 2. Comma-separated match (e.g., "linux,freebsd")
// 3. Unix (for all Unix-like systems)
// 4. All (works on any OS).
func (cd CheckDefinition) CommandsForOS(osName string) []CommandRule {
	// Try exact match first
	if rules := cd.parseRules(osName); rules != nil {
		return rules
	}

	// Check comma-separated keys
	for key := range cd {
		if strings.Contains(key, ",") {
			for part := range strings.SplitSeq(key, ",") {
				if strings.TrimSpace(part) == osName {
					if rules := cd.parseRules(key); rules != nil {
						return rules
					}
					break
				}
			}
		}
	}

	// Check unix for Unix-like systems (all except Windows)
	if osName != "windows" {
		if rules := cd.parseRules("unix"); rules != nil {
			return rules
		}
	}

	// Fall back to "all"
	return cd.parseRules("all")
}

// parseRules converts the raw YAML data into CommandRule slice.
func (cd CheckDefinition) parseRules(key string) []CommandRule {
	val, exists := cd[key]
	if !exists {
		return nil
	}
	if val == nil {
		return nil
	}

	// The value should be a slice of rule maps
	slice, ok := val.([]any)
	if !ok {
		return nil
	}

	if len(slice) == 0 {
		return nil
	}

	var rules []CommandRule
	for _, item := range slice {
		// Each item should be a map
		var ruleMap map[string]any

		switch m := item.(type) {
		case map[string]any:
			ruleMap = m
		case map[any]any:
			// Convert to map[string]interface{}
			ruleMap = make(map[string]any)
			for k, v := range m {
				if ks, ok := k.(string); ok {
					ruleMap[ks] = v
				}
			}
		case CheckDefinition:
			// It's another CheckDefinition, treat it as a map
			ruleMap = map[string]any(m)
		default:
			continue
		}

		if ruleMap == nil {
			continue
		}

		// Build the CommandRule
		rule := CommandRule{}
		if output, ok := ruleMap["output"].(string); ok {
			rule.Output = output
		}
		if file, ok := ruleMap["file"].(string); ok {
			rule.File = file
		}
		if includes, ok := ruleMap["includes"].(string); ok {
			rule.Includes = includes
		}
		if excludes, ok := ruleMap["excludes"].(string); ok {
			rule.Excludes = excludes
		}
		// Handle exitcode which might be unmarshaled as different numeric types
		if exitCode := ruleMap["exitcode"]; exitCode != nil {
			switch v := exitCode.(type) {
			case int:
				rule.ExitCode = &v
			case int64:
				i := int(v)
				rule.ExitCode = &i
			case float64:
				i := int(v)
				rule.ExitCode = &i
			}
		}

		// Handle remediation array
		if rem, ok := ruleMap["remediation"].([]any); ok {
			for _, r := range rem {
				if str, ok := r.(string); ok {
					rule.Remediation = append(rule.Remediation, str)
				}
			}
		}

		// Only add rules that have either output or file
		if rule.Output != "" || rule.File != "" {
			rules = append(rules, rule)
		}
	}

	return rules
}
