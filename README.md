# gitMDM

![Experimental](https://img.shields.io/badge/status-experimental-orange)
![Go Version](https://img.shields.io/github/go-mod/go-version/codeGROOVE-dev/gitMDM)
![License](https://img.shields.io/github/license/codeGROOVE-dev/gitMDM)
![Go Report Card](https://goreportcard.com/badge/github.com/codeGROOVE-dev/gitMDM)
![Platform Support](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20bsd%20%7C%20windows%20%7C%20solaris%20%7C%20plan9%20-blue)

A security-first MDM that manages compliance without compromising your infrastructure.

![logo](./media/logo_small.png "gitMDM logo")

## A Different Approach to Device Management

Traditional MDMs were designed for corporate IT control. They require root access, execute remote commands, and create a massive attack surface. One compromised MDM server can mean game over for your entire fleet.

gitMDM takes a security-first approach. Built on the principle that a compromise of your MDM server shouldn't result in an instant root-level compromise of its clients.

## Features

* Cross-platform (Linux, macOS, *BSD, Solaris, Windows)
* YAML configuration - cryptographically signed using [sigstore](https://sigstore.org/)
* Designed to run as a non-root user
* Uses [git](https://git.org/) as a datastore for a persistent trail of events
* Secure-by-design with a minimal attack surface
* Low maintenance, low dependencies
* Self-hostable on anything from [Google Cloud Run](https://cloud.google.com/run) to a [Raspberry Pi running Plan 9](https://luksamuk.codes/posts/plan9-setup-rpi.html)

## Demo

📺 https://gitmdm.codegroove.dev/ - a real-life unrestricted instance of gitMDM.

## Default Compliance Checks

By default, we verify only what we interpret as required for SOC 2 and ISO 27001 compliance:

- Disk encryption status
- Screen lock configuration
- OS security updates
- Firewall status
- Antivirus presence
- Password policy (NIST 800-63B compliant)

Want different checks? Edit `cmd/agent/checks.yaml`, sign the configuration, and run "make build". The checks are part of the binary, not runtime configuration.

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

Even if an attacker completely owns your server, they cannot modify agent behavior.

NOTE: We plan on making this approach more flexible in the future, but we will always choose secure-by-default.

## Quick Start

### Server-less test of the agent

Want to see what the agent checks for without connecting it to a server? We've got you covered:

```
go run ./cmd/agent/ --run all --verbose
🔍 Running compliance checks...

✅ AVAILABLE UPDATES [PASS]
Command: softwareupdate -l
Output:
  Software Update Tool

  Finding available software
Stderr: No new software available.

Status: OK
...

```

### Client/Server configuration

Build the command-line utilities:

```bash
make all
```

To run the MDM server, there are two options for storage:

* `-git`: the location of a git repo to clone and push to; if it's a local directory, we'll even `git init` the directory for you
* `-clone`: the path to a locally checked out clone of a remote git repo.

```
gitmdm-server -git /var/git
```

By default, the server will generate a join key that clients need to confirm they are talking to the correct server. You can pass in a custom string using `--join scoobysnacks`. If the join key leaks, the worst someone can do is upload garbage compliance data for their machine.

We love Google Cloud Run for our deployment story - check out `./hacks/deploy.sh` to see how our own production infrastructure works.


# Agent

To test the agent against the server, use:

```
gitmdm-agent --server http://localhost:8080 --join KEY
```

To persistently install the agent, add `--install`, which will populate launchd (macOS), task scheduler (Windows), user-systemd (Linux), or cron (elsewhere).

## Security FAQ

**What's the worst-case scenario if my server is compromised?**

Attackers can read compliance reports and trash them. They cannot push commands, install software, or access agent machines.

**How do you prevent supply chain attacks?**
Agents are built from source, checks are compiled in, and with Sigstore integration, all configurations are cryptographically signed with identity verification. Minimal dependencies.

## Contributions

... are very much appreciated. We actually want this to be useful.

---

*Because your security posture shouldn't require the missionary position.*
