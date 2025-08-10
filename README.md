# gitMDM

A security-first MDM that proves compliance without compromising your infrastructure.

![logo](./media/logo_small.png "gitMDM logo")

## A Different Approach to Device Management

Traditional MDMs were designed for corporate IT control. They require root access, execute remote commands, and create a massive attack surface. One compromised MDM server can mean game over for your entire fleet.

gitMDM takes a security-first approach. Built on the principle that even your MDM server shouldn't be trusted with root access to your machines.

## Demo

https://gitmdm.codegroove.dev/ - a real life instance of gitMDM.

### Core Security Principles

**Zero Trust Architecture**: The server cannot execute commands on agents - we didn't just disable it, we never built it. A compromised server gets you compliance reports, not a botnet.

**Defense in Depth**: Agents run as unprivileged users (not root). Checks are compiled into the binary. With Sigstore, configurations are cryptographically signed. Even without signatures, a compromised server can't inject malicious code.

**Minimal Attack Surface**: No listening ports on agents. No remote execution capability. No auto-updates. The agent can only send data, never receive commands. This isn't configurable - it's architectural.

**Transparency Through Simplicity**: Every check we run is visible in `checks.yaml`. The entire codebase is open source. Compliance data is stored in git with immutable history. Security through obscurity is not security.

## What Makes This Secure

Instead of giving servers control over devices, we use a one-way reporting model:

```
[Agent]           [Server]          [Git]
   |                 |                |
   |-- HTTPS ------->|                |
   |   (reports)     |--- git push -->|
   |                 |                |
   X <-- CANNOT -----|                |
       (execute)
```

Even if an attacker completely owns your server, they cannot:
- Execute commands on agents
- Install malware
- Modify agent behavior
- Access sensitive local files
- Pivot to other machines

## Default Compliance Checks

We verify only what's required for SOC 2 and ISO 27001:
- Disk encryption status
- Screen lock configuration
- OS security updates
- Firewall status
- Antivirus presence
- Password policy (NIST 800-63B compliant)

Want different checks? Edit `cmd/agent/checks.yaml` and rebuild. The checks are part of the binary, not runtime configuration.

## Platform Support

Secure on every platform:
- Linux (all distros, all desktop environments)
- macOS (10.15+)
- BSD variants (Free/Open/Net/Dragonfly)
- Windows 10/11
- Solaris/Illumos

## Quick Start

```bash
make all

# Server (git-backed for auditability)
gitmdm-server -git /var/git

# Agent
gitmdm-agent --install --server https://gitmdm.example.com --join KEY
```

We love Google Cloud Run for our deployment story - check out `./hacks/deploy.sh` to see how our own production infrastructure works.

## Security FAQ

**What's the worst case scenario if my server is compromised?**
Attackers can read compliance reports and delete them. That's it. They cannot push commands, install software, or access agent machines.

**Why not just use osquery?**
osquery is powerful but requires careful configuration to avoid information leakage. gitMDM is purpose-built for compliance with security as the primary design constraint.

**How do you prevent supply chain attacks?**
Agents are built from source, checks are compiled in, and with Sigstore integration, all configurations are cryptographically signed with identity verification. Minimal dependencies.

**What about insider threats?**
Even malicious insiders with server access can only view compliance data. To modify agent behavior requires rebuilding and redistributing the binary - leaving an audit trail.

---

*Because your security posture shouldn't require the missionary position.*
