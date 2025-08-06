# gitMDM: The MDM that isn't

![gitMDM Logo](media/logo_small.png)

⚠️ **HIGHLY EXPERIMENTAL - MAY EAT YOUR CAT** ⚠️

## What

A "Mobile Device Management" solution that stores compliance data in Git. Built to pass SOC 2 without requiring a highly privileged RCE

## Why

Because real MDMs are backdoors with compliance features. This just generates the reports auditors want without the ability to actually control your devices.

## Philosophy

- **Can't manage devices** - Only reports on them
- **Can't execute commands** - Read-only by design
- **Can't phone home** - Your Git repo, your control
- **Can't compromise systems** - No privileges, no access

## Architecture

```
Device → Agent (reads) → Server (receives) → Git (stores) → Auditor ✅
```

## Features

Proves compliance without control:
- Disk encryption status
- Firewall configuration
- User accounts
- System updates
- Screensaver locks

## Cross Platform

We currently support:

* Linux
* macOS
* FreeBSD
* OpenBSD
* NetBSD
* DragonFlyBSD
* Solaris
* illumos
* Windows 11

gitMDM supports any architecture supported by the Go programming language: from riscv to ppc64.

## Installation

```bash
# Build
make build

# Server (pick one)
./gitmdm-server -git https://github.com/you/compliance.git  # Clone & push
./gitmdm-server -clone /path/to/repo                        # Use existing

# Agent
./gitmdm-agent -server http://your-server:8080

# Deploy
echo "gitmdm-agent -server http://your-server:8080" | crontab -
```

## GitHub Auth

```bash
# Use SSH (recommended)
./gitmdm-server -git git@github.com:you/compliance.git

# Or GitHub CLI
gh auth setup-git
```

## Configuration

Edit `checks.yaml` to define compliance checks. Default config satisfies most auditors.

## Security

Traditional MDMs: Give someone your house keys to check if the door is locked.
gitMDM: Someone photographs your locked door from across the street.

**Result**: Compliance without compromise.

**Note**: The server accepts reports without authentication by default. While this means anyone could submit false compliance data, they still can't access or control your actual devices. Enable API key authentication (`-api-key`) or use network-level controls if you need to verify report sources.

## Disclaimer

This software proves compliance. It doesn't actually manage devices. That's the point.

---

*Built with spite by someone who wanted to pass SOC 2 with OpenBSD.*
