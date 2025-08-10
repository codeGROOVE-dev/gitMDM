# gitMDM

The SOC-2 compliance solution for the discerningly paranoid security engineer.

![logo](./media/logo_small.png "gitMDM logo")

## What Happens When a Security Engineer Builds an MDM

gitMDM is what you get when you ask a security engineer to make an MDM tool. Traditional MDMs operate on the assumption that the central server is trustworthy and should have root access to execute arbitrary code on all endpoints. We think that's insane.

**Core Security Principle**: A compromise of the MDM server should NOT result in a compromise of all agents reporting to it.

This is why gitMDM:
- **Cannot execute remote commands** - The server literally lacks the code to push commands to agents
- **Uses cryptographic signatures** - All agent configurations are signed with Sigstore, preventing a compromised server from injecting malicious checks
- **Runs without privileges** - Agents run as regular users, not root/SYSTEM
- **Reports only** - Information flows one way: from agents to server, never the reverse

## Your Problem

Your startup just hit the enterprise sales milestone where someone asks "are you SOC 2 compliant?" Meanwhile, your engineering team runs OpenBSD on ThinkPads, Arch on Frameworks, and that one person still dailying Plan 9.

Traditional MDMs run as root, execute arbitrary code from cloud servers, and auto-install binaries downloaded from the internet. Your security engineer just had an aneurysm.

## Our Solution

gitMDM proves compliance without the backdoor:

```
Traditional MDM: "Install our root agent that downloads and executes code from our servers!"
Your Team: "How about no."

gitMDM: "Run a read-only agent as a regular user that only reports"
Your Team: "...continue"
```

### Why Your Security Team Will Actually Approve This

- **Zero Remote Execution**: Can't push commands or install software. The server only receives data.
- **Cryptographically Signed Configs**: All agent configurations require Sigstore signatures. A compromised server can't inject malicious checks.
- **No Auto-Updates**: No downloading binaries from the internet. Updates require YOU to rebuild and redeploy.
- **Runs as User**: No root, no SYSTEM. Can't execute arbitrary code or modify your system.
- **You Own Everything**: Your server, your git repo, your data. No third-party cloud with root access to your fleet.
- **Audit Everything**: Every change is a git commit. `git blame` for compliance.

## Demo

Visit our demo instance at https://gitmdm.codegroove.dev/ - OK, so it's actually our prod instance.

## Quick Start

Build static binaries:

```bash
make all
```

Run a server:

```bash
gitmdm-server -git /var/git
```

If you are a fan of Google Cloud Run, check out `./hacks/deploy.sh` for a deployment script.

On a client, the --install flag establishes persistence:

```bash
$ gitmdm-agent --install --server https://gitmdm.cloud --join XXXX
```

## What compliance items does gitMDM check for?

Only the things that come up in a SOC-2 or ISO 27001 report:

* Antivirus
* Firewall
* Full Disk Encryption
* OS updates
* Password complexity (respecting NIST 800-36B)
* Screen locks

## What kind of bizarre platforms do you support?

```yaml
# Your snowflake setups, our problem:
- MATE on OpenBSD (we see you)
- Sway on Alpine (of course)
- i3 on Debian (classic)
- Whatever that custom Wayland compositor you wrote is
- macOS (10.15+)
- Windows 11/10 (though we've never tried it)
```

## Installation That Respects Your OS

- **Linux**: systemd user service (falls back to cron)
- **(Dragonfly|Net|Free|Open)BSD**: cron
- **macOS**: launchd
- **Windows**: Task Scheduler

We detect 11+ desktop environments because your team refuses to standardize.

## Security Architecture

```
[Agent]           [Server]          [Git]
   |                 |                |
   |-- HTTPS ------->|                |
   |   (reports)     |--- git push -->|
   |                 |                |
   X <-- CANNOT -----|                |
       (execute)
```

The server literally cannot execute commands. We removed the code. It's not there.

### Configuration Integrity via Sigstore

Every agent configuration is cryptographically signed using Sigstore's keyless signing:

```bash
# Sign configuration with your GitHub identity
gitmdm-sign --config cmd/agent/checks.yaml

# Agent verifies signature at runtime
gitmdm-agent --signed-by "github:yourusername@example.com"
```

This means:
- **Configurations are tamper-proof** - Any modification breaks the signature
- **Identity-based trust** - You know exactly who signed each configuration (GitHub, Google, etc.)
- **No key management** - Sigstore handles the PKI complexity
- **Transparency logs** - All signatures are recorded in an immutable ledger

Even if an attacker compromises your server, they cannot:
- Inject malicious compliance checks
- Modify existing check definitions
- Bypass signature verification on agents

### Future: Check-Build-Check

We're building automated remediation that maintains our security principles:
- **Check**: Agent identifies non-compliance
- **Build**: Server generates a fix script (signed, of course)
- **Check**: Agent verifies the fix worked

Even remediation scripts will require cryptographic signatures. No unsigned code execution, ever.

## FAQ

> "What happens if someone compromises the server?"

They get read-only access to compliance reports. They cannot:
- Push commands to agents (no code for it)
- Modify agent behavior (signatures prevent it)
- Install malware (agents don't accept commands)
Perhaps they can clean up the old stale check-in data while they are there.

> "What if someone tampers with the agent?"

They can. It's their machine. They can also lie on spreadsheets. At least this has timestamps.

> "Is this enterprise-ready?"

No. But neither was Stripe when you started using it.

---

*Because your security posture shouldn't require the missionary position.*
