# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

gitMDM is a security-first Mobile Device Management solution designed specifically to pass SOC 2 audits without compromising endpoint security. Built on the principle of "Security Through Inability," it deliberately cannot control or compromise endpoint devices - it can only observe and report compliance status. All device compliance data is stored as markdown files in Git repositories for immutable audit trails.

## Build and Development Commands

### Essential Commands
```bash
# Build both server and agent
make build

# Run tests
make test

# Run linting (must pass without errors)
make lint

# Build and run server locally
make run-server

# Build and run agent locally  
make run-agent

# Cross-compile for all platforms
make build-all

# Update dependencies
make deps
```

### Testing Individual Components
```bash
# Run a single compliance check (for testing)
./gitmdm-agent -check hostname

# Test agent against local server
./gitmdm-agent -server http://localhost:8080
```

## Architecture

### Core Components

**Server** (`cmd/server/main.go`)
- Single binary serving both API and web UI
- Stores device reports in Git via `gitstore` package
- Key endpoints:
  - POST `/api/v1/report` - Receives agent compliance reports
  - GET `/api/v1/devices` - Returns device list as JSON
  - GET `/device/{id}` - Web UI for individual device details

**Agent** (`cmd/agent/main.go`)
- Polls server every 5 minutes (configurable via `-interval`)
- Executes compliance checks from `checks.yaml`
- Reports results as JSON to server

**Git Store** (`internal/gitstore/store.go`)
- Thread-safe Git operations with mutex protection
- Stores device data under `/devices/<hardware-id>/` 
- Each compliance check result saved as separate markdown file
- Auto-commits changes with descriptive messages

### Data Flow
1. Agent executes shell commands defined in `checks.yaml`
2. Agent sends JSON report to server's `/api/v1/report`
3. Server validates and stores report via gitstore
4. Gitstore commits markdown files to Git repository
5. Web UI reads from Git to display compliance status

## Key Development Patterns

### Context Usage
Always pass context from main, never create within libraries:
```go
func ProcessDevice(ctx context.Context, device *types.Device) error
```

### Error Handling
Use error wrapping with `%w` for proper error chains:
```go
return fmt.Errorf("failed to execute check %s: %w", check.Name, err)
```

### Thread Safety
Protect shared state with mutexes:
```go
s.mu.Lock()
defer s.mu.Unlock()
```

### Command Execution
Always use timeouts for external commands:
```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
cmd := exec.CommandContext(ctx, "sh", "-c", check.Command)
```

## Platform-Specific Compliance Checks

Compliance checks are defined in `checks.yaml` with platform-specific sections:
- `checks_all`: Runs on all platforms
- `checks_openbsd`, `checks_freebsd`, `checks_darwin`, `checks_linux`: Platform-specific

When adding new checks, ensure they:
1. Have appropriate timeouts
2. Handle command failures gracefully
3. Limit output to prevent data exposure
4. Work across target platforms

## Critical Security Design Principles

This project prioritizes security above all else, with deliberate design constraints:

### Security Through Inability
- **No Remote Execution**: Server CANNOT execute commands on agents - communication is one-way only
- **No Privilege Escalation**: Agents run with minimal permissions and cannot modify system state
- **No Backdoors**: Even if the server is completely compromised, it cannot be used to access endpoints
- **Read-Only Operations**: Agents can only read system state, never modify it
- **Limited Data Collection**: Output strictly limited to prevent information disclosure

### Defense in Depth
- **Minimal Attack Surface**: ~1000 lines of Go code, single YAML dependency
- **Git-Based Audit Trail**: All changes tracked, signed, and immutable
- **No Persistent State**: Server maintains no database; Git is the only storage
- **Fail-Safe Defaults**: Operations fail closed, not open
- **Isolation**: Agent and server components are completely decoupled

### Operational Security
- Agent runs as non-root user
- Command output limited to 10KB per check
- All paths validated before Git operations
- Minimal dependencies (only `gopkg.in/yaml.v3`)
- Distroless container images for deployment
- No cloud dependencies or phone-home behavior

**IMPORTANT**: Any changes that would allow the server to control agents or increase privileges must be rejected. The inability to compromise endpoints is a feature, not a bug.