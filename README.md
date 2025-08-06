
# gitMDM: The MDM that isn't a giant security hole

![gitMDM Logo](media/logo.png)

⚠️ **HIGHLY EXPERIMENTAL - IT MAY EAT YOUR CAT ** ⚠️

## What Is This Thing?

gitMDM is what happens when you need to pass a SOC 2 audit but refuse to sell your soul to the MDM industrial complex. It's a Mobile Device Management solution that stores everything in Git because, apparently, Git is the hammer and everything looks like a nail.

## Why Does This Exist?

Because I needed to prove my devices were "compliant" for SOC 2, but I'll be damned if I'm going to:
- Install some bloated enterprise MDM that phones home every 5 seconds
- Give some cloud service root access to my machines
- Sacrifice my freedom of choice on the altar of compliance theater - if I want to run OpenBSD, I should be able to.
- Trust my device security to a system that's one CVE away from being everyone's backdoor

So I built this instead. It checks boxes. Literally. For auditors.

## Design Philosophy: Paranoia as a Service

- **No Remote Control**: This MDM can't actually manage your devices. It just tattles on them. To Git.
- **No Backdoors**: The server can't execute commands on agents, or itself.
- **No Cloud**: Your compliance data lives in a Git repo you control, not in someone else's computer. You can run it in the Cloud, though.
- **No Privileges**: The agent runs with minimal permissions and couldn't compromise your system if it tried (which it won't, because it can't)
- **No Dependencies**: Well, except for Git. And Go. And YAML. But who's counting?
- **No Support**: You're on your own, friend. I built this for me.

## How It "Works"

1. **Agent**: A tiny Go binary runs on your devices, executes read-only compliance checks, and sends reports to...
2. **Server**: Another tiny Go binary that receives reports and commits them to...
3. **Git**: Because if you're going to store compliance data somewhere, it might as well have version control

```
Your Device → Agent → Server → Git → Auditor's Spreadsheet → ✅ SOC 2 Compliant!
```

## Features

- ✅ Proves your disk is encrypted (without being able to decrypt it)
- ✅ Shows your firewall is on (without being able to turn it off)
- ✅ Lists your users (without being able to delete them)
- ✅ Reports installed updates (without being able to install them)
- ✅ Demonstrates screensaver locks (without locking you out)
- ✅ Makes auditors happy (without making you sad)
- ✅ Supports pretty much any operating-system, from macOS to Linux to OpenBSD.

## Security Through Inability

Traditional MDMs are like giving someone the keys to your house so they can check if you locked the door. gitMDM is like having someone take a photo of your locked door from across the street. Sure, they can't verify the windows are locked, but they also can't break in.

**Core Security Principles:**
- **Read-Only**: Agents can look but can't touch
- **One-Way Communication**: Agents report to server, server can't command agents
- **Git-Based Audit Trail**: Every change is tracked, signed, and immutable
- **Minimal Attack Surface**: ~1000 lines of Go and one YAML dependency
- **Defense in Depth**: Even if compromised, the server can't compromise endpoints

## Installation

```bash
# Clone it
git clone https://github.com/you/gitMDM.git

# Build it
make build

# Run it (server) - pick your storage poison:

# Option 1: Clone a remote/local repo to temp directory (will push/pull)
./gitmdm-server -git https://github.com/you/compliance-data.git -port 8080

# Option 2: Use an existing local git clone (will push/pull if remote configured)
./gitmdm-server -clone /path/to/your/compliance-repo -port 8080

# Deploy it (agent)
./gitmdm-agent -server http://your-server:8080

# Forget about it
echo "gitmdm-agent -server http://your-server:8080" | crontab -
```

### Git Storage Options

The server needs somewhere to store your compliance data. You have options:

**`-git <url>`** - Clones a repository to a temporary directory
- Works with GitHub/GitLab/Bitbucket: `https://github.com/user/repo.git`
- Works with local repos: `/path/to/repo.git` or `../my-repo`
- Will push/pull changes with the remote
- Fresh clone each time the server starts

**`-clone <path>`** - Uses an existing local git clone
- Works directly in your existing repository
- Will push/pull if the clone has a remote configured
- Useful for testing or when you need specific git configurations
- No temp directory shenanigans

### GitHub Authentication (Because Security Theater Needs Credentials)

If you're using GitHub for your compliance data:

```bash
# Option 1: GitHub CLI (easiest)
gh auth setup-git

# Option 2: SSH keys (most reliable)
# Add your SSH key to GitHub, then:
./gitmdm-server -git git@github.com:you/compliance-data.git

# Option 3: Personal Access Token (for HTTPS)
# Create a PAT on GitHub, then:
./gitmdm-server -git https://TOKEN@github.com/you/compliance-data.git
```

**Pro tip**: Don't commit your tokens. Use SSH keys like a civilized person.

## Configuration

Edit `checks.yaml` to define what compliance theater you want to perform. The default checks should satisfy most auditors who've never actually used a computer.

## Platform Support

- macOS: Where I live
- Linux: Where servers live
- OpenBSD: Where the paranoid live
- FreeBSD: Where the... uh... FreeBSD people live
- Windows: LOL no

## Known Issues

- May not actually eat your cat, but no promises
- Definitely won't manage your mobile devices despite the name
- Auditors might ask "is this really an MDM?" (Answer: "It's better, it's *compliant*")
- You might be the second user, which would break our metrics

## Disclaimer

This software is provided "as is" without warranty of any kind. It probably won't eat your cat, compromise your devices, or make you fail your audit. But if it does, you can keep both pieces.

**Remember**: The 'M' in MDM stands for 'Minimal' (in this case).

---

*Built with ❤️ and spite by someone who just wanted to pass an audit with their OpenBSD laptop.*
