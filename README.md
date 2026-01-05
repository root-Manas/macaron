# Macaron v2 🍪

A beautiful, fast security reconnaissance CLI with modern UI. Chains 30+ recon tools with optimized pipelines, progress bars, and Discord notifications.

```
███╗   ███╗ █████╗  ██████╗ █████╗ ██████╗  ██████╗ ███╗   ██╗
████╗ ████║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
██╔████╔██║███████║██║     ███████║██████╔╝██║   ██║██╔██╗ ██║
██║╚██╔╝██║██╔══██║██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║
██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                    v2.0 - Security Recon Platform
```

## ✨ What's New in v2

- **🎨 Beautiful UI** - Progress bars, spinners, colored output with Rich library
- **⚡ Simplified CLI** - Short flags: `-s` scan, `-S` status, `-R` results, `-L` tools
- **🚀 Three Scan Modes** - `wide`, `narrow`, and NEW `fast` mode
- **🔧 Optimized Pipeline** - Better tool chaining with proper rate limits
- **📊 Live Progress** - See each tool running with progress tracking

## 🚀 Quick Start

```bash
# Install
chmod +x macaron && sudo cp macaron /usr/local/bin/
pip install rich  # For beautiful UI
sudo macaron -I   # Install recon tools

# Scan!
macaron -s example.com           # Wide scan (default)
macaron -s app.com -n            # Narrow scan (app-focused)
macaron -s target.com -f         # Fast scan (quick wins)
macaron -s target.com --slow     # Slow mode (ISP friendly)
```

## 📋 Command Reference

| Short | Long | Description |
|-------|------|-------------|
| `-s TARGET` | `--scan` | Scan target(s) |
| `-S` | `--status` | Show status & summary |
| `-R` | `--results` | Show scan results |
| `-L` | `--list-tools` | List installed tools |
| `-E` | `--export` | Export results to JSON |
| `-I` | `--install` | Install recon tools (sudo) |
| `-C` | `--config` | Show configuration |

### Scan Options

| Flag | Description |
|------|-------------|
| `-n` | Narrow mode (app-focused) |
| `-f` | Fast mode (minimal tools) |
| `-F FILE` | Targets from file |
| `--stdin` | Read from stdin |
| `--slow` | Slow mode (10 req/s) |
| `--no-proxy` | Disable proxychains |
| `-q` | Quiet mode |

### Results Options

| Flag | Description |
|------|-------------|
| `-d DOMAIN` | Filter by domain |
| `-w TYPE` | What to show: subdomains, live, ports, urls, js, vulns |
| `--limit N` | Limit results (default: 50) |

## 📋 Scan Modes

### 🔍 WIDE Mode (Default)
Full infrastructure reconnaissance:
```
1. Subdomain Discovery  →  subfinder, amass, assetfinder, findomain, crt.sh
2. DNS Resolution       →  dnsx (with retries)
3. Port Scanning        →  naabu (top 1000)
4. HTTP Probing         →  httpx (tech-detect, CDN)
5. URL Discovery        →  gau, waybackurls, katana
6. JS Analysis          →  getJS
7. Screenshots          →  gowitness
8. Vuln Scanning        →  nuclei
```

### 🎯 NARROW Mode (-n)
Application-focused testing:
```
1. DNS Validation       →  dnsx
2. Light Port Scan      →  naabu (web ports only)
3. HTTP Probing         →  httpx
4. Deep Crawling        →  katana (depth 4), hakrawler
5. URL Archives         →  gau, waybackurls
6. JS Analysis          →  getJS
7. Content Discovery    →  ffuf
8. Screenshots          →  gowitness
9. Vuln Scanning        →  nuclei (focused)
```

### ⚡ FAST Mode (-f)
Quick wins, minimal time:
```
1. Quick Subdomains     →  subfinder, crt.sh
2. HTTP Probing         →  httpx
3. Quick Vuln Scan      →  nuclei (critical+high only)
```

## 💻 Examples

```bash
# Infrastructure recon on bug bounty target
macaron -s hackerone.com

# Application testing
macaron -s https://api.example.com -n

# Multiple targets from file
macaron -s -F scope.txt

# Quick scan for immediate wins
macaron -s target.com -f

# Slow and stealthy (avoids rate limits)
macaron -s target.com --slow

# Check results
macaron -S                    # Status summary
macaron -R                    # All results
macaron -R -d example.com     # Specific domain
macaron -R -w vulns           # Vulnerabilities only

# List tools
macaron -L

# Export for reporting
macaron -E -o report.json

# Configure Discord webhook
macaron --webhook "https://discord.com/api/webhooks/..." --test
```

## 🛠️ Tool Pipeline (Optimized)

Each tool is configured with optimal flags discovered from `-h` analysis:

| Tool | Key Optimizations |
|------|-------------------|
| **subfinder** | `-all -t 25` (all sources, parallel) |
| **amass** | `-passive -dns-qps 50` (rate limited) |
| **dnsx** | `-a -resp -json -t 100` (fast resolve) |
| **naabu** | `-top-ports 1000 -retries 2` (reliable) |
| **httpx** | `-sc -title -td -cdn` (full detection) |
| **katana** | `-jc -iqp -d 3` (JS crawling, dedup) |
| **gau** | `--subs --threads 5` (include subs) |
| **nuclei** | `-rl 100 -c 25 -nh` (rate limited) |
| **gowitness** | `scan file --delay 2` (v3 API) |

## 📁 Output Structure

```
~/.macaron/
├── config/
│   └── config.json       # Configuration
├── data/
│   └── <target>/
│       ├── subdomains.txt
│       ├── resolved.txt
│       ├── ports.txt
│       ├── live_hosts.txt
│       ├── technologies.txt
│       ├── urls.txt
│       ├── js_files.txt
│       ├── summary.json
│       ├── nuclei.json
│       └── screenshots/
├── state/
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
```

## 📱 Discord Notifications

```bash
macaron --webhook "https://discord.com/api/webhooks/..." --test
```

Notifications for:
- 🚀 Scan started
- ✅ Scan completed (with stats)
- ⚠️ Vulnerabilities found (critical/high)

## 🎨 UI Preview

The new v2 interface shows:
- Real-time progress bars per tool
- Stage completion summaries
- Color-coded vulnerability counts
- Beautiful summary tables

## License

MIT - Use responsibly for authorized testing only.
