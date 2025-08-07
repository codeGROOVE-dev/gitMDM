# gitMDM

Security-first compliance reporting that doesn't compromise your infrastructure.

![gitMDM Logo](media/logo_small.png)

## The Problem

Every MDM is a backdoor. They typically require root access and arbitrary remote code execution. They're incompatible with secure-by-default operating systems. Yet auditors require them for SOC 2.

## The Solution

gitMDM proves compliance without compromising security:
- **No arbitrary remote code execution** - Checks are compiled into the agent binary
- **No privileged access** - Runs as a normal user
- **No phone-home** - Your git repo, your endpoint, your control
- **Works everywhere** - Including secure-by-default systems such as OpenBSD.

## Screenshots

### Device List
<a href="media/dashboard.png"><img src="media/dashboard.png" alt="Dashboard" width="400"/></a>

### Device Details

<a href="media/report.png"><img src="media/report.png" alt="Agent Report" width="400"/></a>

### Remediation
<a href="media/remediate.png"><img src="media/remediate.png" alt="Remediation Steps" width="400"/></a>

## How It Works

```
[Agent]                    [Server]                   [Git]
Run compiled checks  →  Receive reports only  → Tamper-resistant audit trail
```

The server **cannot** push commands. Ever. That's the point.

## Quick Start

```bash
# Server - now with 100% less git CLI dependency!
# Auto-generates a join key from hardware ID if you're too lazy to set one
./gitmdm-server -git /path/to/compliance  # Creates repo if it doesn't exist
# or
./gitmdm-server -clone /existing/repo      # Uses existing local repo

# The server will display something like:
# ═══════════════════════════════════════════════════════════════
# GitMDM Server Started
# Join Key: 926DD23A5B
# 
# To register an agent, run:
#   ./gitmdm-agent --server http://localhost:8080 --join 926DD23A5B
# ═══════════════════════════════════════════════════════════════

# Agent - checks in every 20 minutes (because 5 was too clingy)
./gitmdm-agent --server http://localhost:8080 --join 926DD23A5B
```

### Environment Variables (for the Docker crowd)

```bash
# Server accepts these if you're allergic to flags
export GIT_REPO=git@github.com:org/compliance.git
export PORT=8080
export JOIN_KEY=SUPERSECRET123  # Or let it auto-generate one
./gitmdm-server
```

## Local Checks

You can run the compliance checks even without a server:

```bash
./out/gitmdm-agent -run all
```

You'll see output similar to:

```log
🔍 Running security checks...

⚠️  3 issues require attention

🔸 screen lock
   🐞 Problem: Screen idle time too long (1 hour, SOC 2 requires ≤15 min); Screen lock delay too long (4 hours, SOC 2 requires ≤15 min)
   💻 Evidence: defaults -currentHost read com.apple.screensaver idleTime && sysadminctl -screenLock status

   🔧 How to fix:
      1. Open System Settings > Lock Screen
      2. Set 'Start Screen Saver when inactive' to 15 minutes or less
      3. Open System Settings > Lock Screen
      4. Set 'Require password after screen saver begins' to 'immediately'
```

## What You Get

SOC 2 compliance evidence in git:
```
devices/
├── 926DD23A5B/                    # Hardware IDs, not names (privacy!)
│   ├── info.json                  # Device metadata
│   ├── disk_encryption.json       ✓
│   ├── screen_lock.json          ✓ 
│   └── firewall.json             ✓
└── README.md                      # Auto-created, unlike this one
```

Every check, every change, in git. No database to corrupt, no API to hack.

## Supported Platforms

Linux, macOS, Windows, FreeBSD, OpenBSD, NetBSD, DragonFlyBSD, Solaris, illumos

## checks.yaml

```yaml
checks:
  disk_encryption:
    openbsd: "bioctl softraid0 | grep -q CRYPTO"
    linux: "lsblk -o NAME,FSTYPE | grep -q crypto_LUKS"
    darwin: "fdesetup status | grep -q 'On'"
```

Edit, compile, deploy. No runtime configuration files to tamper with.

## Security Guarantees

- **Server compromise = read-only access to compliance reports** (and they're in git anyway)
- **No arbitrary code execution** - Not even with root on the server
- **Agent decides what runs** - Compiled-in checks, not runtime shenanigans
- **Bash restricted mode** - When we absolutely must shell out
- **No git CLI required** - Pure Go implementation (go-git), works in containers
- **Join key required** - Keeps the riffraff out of your compliance data

## Building

```bash
make all
```

Compiles to static binaries because dynamic linking is for people who enjoy debugging production at 3 AM.

## Code Philosophy

Written in Go, blessed by Rob Pike's simplicity principles:
- Functions read like recipes, not puzzle boxes
- No clever abstractions that require a PhD to understand  
- Minimal dependencies (yaml, retry, go-git - that's it!)
- If a function is <7 lines and called once, it's inlined
- Security through simplicity, not complexity theater

## FAQ

**Q: Is this SOC 2 compliant?**  
A: It generates the reports auditors need. Without the backdoors.

**Q: What if we need to change checks?**  
A: Rebuild and redeploy. Immutability is a feature, not a bug.

**Q: Why git?**  
A: Cryptographic proof, audit trail, existing tooling, no database to "accidentally" DROP.

**Q: Does it need git installed?**  
A: Nope! Uses go-git. Works in your hipster minimal container.

**Q: What's a join key?**  
A: A speed bump for script kiddies. Not Fort Knox, but keeps honest people honest.

**Q: Why 20-minute check-ins?**  
A: Because 5 minutes was needy, and daily was negligent. Goldilocks would approve.

---

*Built for organizations that refuse to compromise security for compliance.*
