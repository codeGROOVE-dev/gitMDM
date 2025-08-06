# gitMDM

Security-first compliance reporting that doesn't compromise your infrastructure.

## The Problem

Every MDM is a backdoor. They typically require root access and arbitrary remote code execution. They're incompatible with secure-by-default operating systems. Yet auditors require them for SOC 2.

## The Solution

gitMDM proves compliance without compromising security:
- **No arbitrary remote code execution** - Checks are compiled into the agent binary
- **No privileged access** - Runs as a normal user
- **No phone-home** - Your git repo, your endpoint, your control
- **Works everywhere** - Including secure-by-default systems such as OpenBSD.

## How It Works

```
[Agent]                    [Server]                   [Git]
Run compiled checks  →  Receive reports only  →  Immutable audit trail
```

The server **cannot** push commands. Ever. That's the point.

## Quick Start

```bash
# Server
./gitmdm-server -git git@github.com:org/compliance.git -api-key SECRET

# Agent (checks compiled in from checks.yaml)
./gitmdm-agent -server https://server:8080
```

## What You Get

SOC 2 compliance evidence in git:
```
devices/laptop-alice/disk_encryption.json  ✓
devices/laptop-alice/screen_lock.json      ✓
devices/server-prod/firewall.json          ✓
```

Every check, every change, cryptographically signed and timestamped.

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

- Server compromise = read-only access to compliance reports
- No arbitrary code execution, even with root on the server
- Agent decides what runs based on compiled-in checks
- Bash restricted mode when shell execution is needed

## Building

```bash
vim checks.yaml  # Define your compliance checks
make build       # Compiles checks into binary
```

## FAQ

**Q: Is this SOC 2 compliant?**
A: It generates the reports auditors need. Without the backdoors.

**Q: What if we need to change checks?**
A: Rebuild and redeploy. Immutability is a feature.

**Q: Why git?**
A: Cryptographic proof, audit trail, existing tooling, no database.

---

*Built for organizations that refuse to compromise security for compliance.*
