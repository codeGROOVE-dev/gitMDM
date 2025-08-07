# gitMDM 🧪

The MDM for startups that actually care about security.

## Your Problem

Your startup just hit the enterprise sales milestone where someone asks "are you SOC 2 compliant?" Meanwhile, your engineering team runs OpenBSD on ThinkPads, Arch on Frameworks, and that one person still dailying Plan 9. 

Traditional MDMs run as root, execute arbitrary code from their cloud servers, and auto-install binaries downloaded from the internet. Your security engineer just had an aneurysm.

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
- **No Auto-Updates**: No downloading binaries from the internet. Updates require YOU to rebuild and redeploy.
- **Runs as User**: No root, no SYSTEM. Can't execute arbitrary code or modify your system.
- **You Own Everything**: Your server, your git repo, your data. No third-party cloud with root access to your fleet.
- **Audit Everything**: Every change is a git commit. `git blame` for compliance.

## Quick Start for the Impatient

```bash
# On your secure server (or laptop, we don't judge)
./gitmdm-server -git /opt/compliance

# On your OpenBSD machine
$ doas pkg_add gitmdm-agent  # just kidding, compile it yourself
$ ./gitmdm-agent --install --server https://comply.internal --join XXXX

# On your Linux laptop  
$ ./gitmdm-agent --install --server https://comply.internal --join XXXX

# On that Mac the designer insisted on
$ ./gitmdm-agent --install --server https://comply.internal --join XXXX
```

Join keys stored in `~/.config/gitmdm/` (or wherever your OS says), not in process lists.

## What SOC 2 Actually Requires vs What We Check

| SOC 2 Says | Traditional MDMs Do | We Do |
|------------|---------------------|--------|
| Disk encryption | Run as root to verify and enforce | Check encryption status as user |
| Screen locks | Execute scripts as root to enforce policies | Read your existing screensaver config |
| OS updates | Download and install updates as root | Report current version numbers |
| Firewall enabled | Execute commands as root to modify rules | Check firewall status (read-only) |

## Platform Detection That Actually Works

```yaml
# Your snowflake setups, our problem:
- MATE on OpenBSD (we see you)
- Sway on Alpine (of course)  
- i3 on Debian (classic)
- Whatever that custom Wayland compositor you wrote is
- Even macOS (unfortunate, but supported)
```

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

## For Your Compliance Team

"How do we prove compliance?"

```bash
$ cd compliance-repo
$ git log --oneline
8f3d2a1 workstation-42: disk encryption enabled
7b2c3f9 laptop-dev-3: screen lock fixed
5a1e8c4 desktop-1: firewall enabled
```

"What if someone tampers with the agent?"

They can. It's their machine. They can also lie on spreadsheets. At least this has timestamps.

"Is this enterprise-ready?"

No. But neither was Stripe when you started using it.

## Building

```bash
make all  # Static binaries, because dynamic linking is attack surface
```

No npm. No pip. No containers. Just Go.

## Installation That Respects Your OS

- **Linux**: systemd user service (falls back to cron if you're systemd-free)
- **OpenBSD**: cron (because rc.d requires root and we're not animals)
- **macOS**: launchd (the least worst option)
- **FreeBSD/NetBSD**: cron (see OpenBSD)

Pre-flight check ensures the server exists before installing. Novel concept.

## FAQ for Security-Conscious Teams

**Q: Can this execute remote commands?**  
A: No. Check the code. The handler doesn't exist.

**Q: What about supply chain attacks?**  
A: It's 2 dependencies: yaml and retry. Vendor them if paranoid.

**Q: Does it require root?**  
A: Never. User-level only. Just reads system configuration.

**Q: What data does it collect?**  
A: Read `checks.yaml`. It's compiled in. No surprises.

**Q: Can we self-host?**  
A: That's the only option. There's no cloud service. You run it.

**Q: What if an agent is compromised?**  
A: It can lie about that device's compliance. That's it. No lateral movement.

**Q: OpenBSD pledge/unveil support?**  
A: On the roadmap. PRs welcome from fellow paranoids.

---

*Built by engineers who rm -rf node_modules on principle.*

**⚠️ EXPERIMENTAL**  
*But still more trustworthy than your current MDM.*

*Remember: Compliance theater is still theater, but at least our stage doesn't have backdoors.*

---

*"Because compliance doesn't require compromise."*