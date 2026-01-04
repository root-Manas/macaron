# Security Recon Platform 🔍

A single unified CLI tool for automated security reconnaissance. Chains all recon tools efficiently, filters targets for manual testing, and sends Discord notifications.

```
███╗   ███╗ █████╗  ██████╗ █████╗ ██████╗  ██████╗ ███╗   ██╗
████╗ ████║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
██╔████╔██║███████║██║     ███████║██████╔╝██║   ██║██╔██╗ ██║
██║╚██╔╝██║██╔══██║██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║
██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
```

## 🎯 Features

- **Single CLI Tool** - One command for everything: `macaron`
- **Two Scan Modes**:
  - `wide` - Full infrastructure recon (subdomains → DNS → ports → HTTP → URLs → vulns)
  - `narrow` - Application-specific (crawling, content discovery, focused vuln scan)
- **Chained Pipeline** - Each stage automatically feeds into the next
- **30+ Tools** - subfinder, amass, httpx, nuclei, katana, gau, and more
- **Proxychains** - All scans go through proxychains to avoid rate limiting
- **Auto-Resume** - Picks up where it left off on device restart
- **Discord Alerts** - Get notified for vulnerabilities and scan progress
- **Smart Scanning** - Only scans resolved/live hosts

## 🚀 Quick Start

### Install

```bash
# In WSL/Kali
git clone <repo> macaron && cd macaron
chmod +x install-macaron.sh && ./install-macaron.sh
```

Or manual:
```bash
chmod +x macaron
sudo cp macaron /usr/local/bin/
sudo macaron install  # Install recon tools
```

### Usage

```bash
# Wide mode - Infrastructure recon (subdomains, ports, everything)
macaron scan -t example.com

# Narrow mode - Application-specific testing
macaron scan -t https://app.example.com -m narrow

# Multiple targets
macaron scan -t target1.com target2.com

# From file
macaron scan -f targets.txt

# Pipe from stdin
echo "example.com" | macaron scan --stdin

# Without proxychains (faster but may get rate limited)
macaron scan -t example.com --no-proxy

# Resume interrupted scan
macaron scan --resume
```

## 📋 Scan Pipelines

### WIDE Mode (Infrastructure)
```
Stage 1: Subdomain Discovery  →  subfinder, amass, assetfinder, findomain, crt.sh, chaos
Stage 2: DNS Resolution       →  dnsx
Stage 3: Port Scanning        →  naabu
Stage 4: HTTP Probing         →  httpx (with tech detection)
Stage 5: URL Discovery        →  gau, waymore, waybackurls, katana
Stage 6: JS Analysis          →  getJS, linkfinder
Stage 7: Screenshots          →  gowitness, eyewitness
Stage 8: Vuln Scanning        →  nuclei
```

### NARROW Mode (Application)
```
Stage 1: HTTP Probing         →  httpx
Stage 2: Deep Crawling        →  katana, hakrawler  
Stage 3: URL Discovery        →  gau, waymore
Stage 4: JS Analysis          →  getJS, linkfinder
Stage 5: Content Discovery    →  ffuf
Stage 6: Screenshots          →  gowitness
Stage 7: Vuln Scanning        →  nuclei (focused templates)
```

## 💻 All Commands

```bash
# Scanning
macaron scan -t example.com              # Wide scan (default)
macaron scan -t example.com -m narrow    # Narrow scan
macaron scan -f targets.txt              # From file
macaron scan --stdin                     # From pipe
macaron scan --resume                    # Resume last scan
macaron scan -t target.com --no-proxy    # Without proxychains
macaron scan -t target.com --threads 100 # Custom thread count

# Target management
macaron add example.com target.com       # Save targets
macaron list targets                     # Show saved targets

# Tools
macaron install                          # Install all tools (sudo)
macaron list tools                       # Show installed tools

# Results
macaron list results                     # Show scan results
macaron export -o results.json           # Export all data
macaron export -d example.com            # Export single domain

# Configuration  
macaron config show                      # Show config
macaron config set --key KEY --value VAL # Set config value
macaron config webhook --url URL --test  # Set Discord webhook
```

## 🛠️ Tools Included

| Category | Tools |
|----------|-------|
| **Subdomain Enum** | subfinder, amass, assetfinder, findomain, chaos, crt.sh |
| **DNS Resolution** | dnsx, massdns |
| **Port Scanning** | naabu, masscan, nmap |
| **HTTP Probing** | httpx (with tech detection) |
| **URL Discovery** | gau, waymore, waybackurls, katana, hakrawler |
| **JS Analysis** | getJS, linkfinder, secretfinder |
| **Content Discovery** | ffuf, feroxbuster, dirsearch |
| **Vuln Scanning** | nuclei |
| **Screenshots** | gowitness, eyewitness |

## ⚙️ Configuration

Config stored in `~/.macaron/config/config.json`

```bash
# Set Discord webhook
macaron config webhook --url "https://discord.com/api/webhooks/..." --test

# Enable/disable features
macaron config set --key proxy.enabled --value true
macaron config set --key discord.enabled --value true

# Add API keys
macaron config set --key api_keys.chaos --value "YOUR_KEY"
```

## 📁 Output Structure

```
~/.macaron/
├── config/
│   ├── config.json       # Configuration
│   └── targets.txt       # Saved targets
├── data/
│   └── <target>/
│       ├── subdomains.txt
│       ├── resolved.txt
│       ├── ports.txt
│       ├── live_hosts.txt
│       ├── technologies.txt
│       ├── urls.txt
│       ├── js_files.txt
│       ├── endpoints.txt
│       ├── summary.json
│       ├── screenshots/
│       └── vulnerabilities/
├── state/
│   └── scan_state.json   # For resume
├── logs/
└── wordlists/
    └── common.txt
```

## 🔒 Proxychains Setup

Configure `/etc/proxychains4.conf`:

```conf
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 9050   # Tor
# Or your own proxies
```

## 🔄 Auto-Resume

Set up auto-resume on boot:
```bash
# Add to crontab
(crontab -l; echo "@reboot macaron scan --resume") | crontab -
```

Or use the installer which sets this up automatically.

## 📱 Discord Notifications

Get notified for:
- 🚀 Scan started
- ✅ Scan completed (with stats)
- ⚠️ Vulnerabilities found (critical/high)
- ❌ Errors

## 📊 Examples

```bash
# Full infrastructure recon on a bug bounty target
macaron scan -t hackerone.com

# Application testing on a specific web app
macaron scan -t https://api.example.com -m narrow

# Scan multiple targets quietly
macaron scan -f scope.txt -q

# Export results for reporting
macaron export -o report.json
```

## License

MIT - Use responsibly for authorized testing only.
