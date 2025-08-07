// Package config defines configuration structures for gitMDM checks.
package config

// Config represents the complete checks configuration.
type Config struct {
	Checks map[string]CheckDefinition `yaml:"checks"`
}

// CheckDefinition defines how a check should be performed across different platforms.
// Field names follow Go build tag conventions.
type CheckDefinition struct {
	Description string        `yaml:"description,omitempty"`
	All         []CommandRule `yaml:"all,omitempty"`
	Unix        []CommandRule `yaml:"unix,omitempty"`      // All Unix-like systems (not Windows)
	Darwin      []CommandRule `yaml:"darwin,omitempty"`    // macOS
	Linux       []CommandRule `yaml:"linux,omitempty"`     // Linux
	Windows     []CommandRule `yaml:"windows,omitempty"`   // Windows
	FreeBSD     []CommandRule `yaml:"freebsd,omitempty"`   // FreeBSD
	OpenBSD     []CommandRule `yaml:"openbsd,omitempty"`   // OpenBSD
	NetBSD      []CommandRule `yaml:"netbsd,omitempty"`    // NetBSD
	Dragonfly   []CommandRule `yaml:"dragonfly,omitempty"` // DragonflyBSD (Go uses "dragonfly")
	Solaris     []CommandRule `yaml:"solaris,omitempty"`   // Solaris/OpenSolaris
	Illumos     []CommandRule `yaml:"illumos,omitempty"`   // Illumos
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
	// Check exact OS match first
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
	}

	// Check unix for Unix-like systems (all except Windows)
	if osName != "windows" && len(cd.Unix) > 0 {
		return cd.Unix
	}

	// Fall back to "all"
	return cd.All
}
