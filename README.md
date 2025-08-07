# gitMDM

The SOC-2 compliance solution for the discerningly paranoid security engineer.

![logo](./media/logo_small.png "gitMDM logo")

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

## FAQ

> "What happens if someone compromises the server?"

Nothing. Perhaps they can clean up the old stale check-in data while they are there.

> "What if someone tampers with the agent?"

They can. It's their machine. They can also lie on spreadsheets. At least this has timestamps.

> "Is this enterprise-ready?"

No. But neither was Stripe when you started using it.

---

*Because your security posture shouldn't require the missionary position.*
