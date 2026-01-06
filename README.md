# Macaron v2.3 - Security Reconnaissance Platform

```
███╗   ███╗ █████╗  ██████╗ █████╗ ██████╗  ██████╗ ███╗   ██╗
████╗ ████║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
██╔████╔██║███████║██║     ███████║██████╔╝██║   ██║██╔██╗ ██║
██║╚██╔╝██║██╔══██║██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║
██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
```

**A powerful CLI-based security reconnaissance platform for bug bounty hunters**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🎯 Overview

Macaron is a comprehensive security reconnaissance platform designed for bug bounty hunters and security researchers. It automates asset discovery through intelligent tool orchestration and stores all data for manual testing.

**Key Features**:
- 🔍 Subdomain discovery & permutation (subfinder, amass, dnsgen, altdns)
- 🌍 ASN & IP range discovery (asnmap, amass intel)
- 🌐 HTTP probing with tech detection (httpx, whatweb)
- 🔓 Port scanning (naabu, masscan)
- 🕷️ Deep crawling & URL mining (katana, gau, gospider)
- ⚙️ Parameter discovery (paramspider, arjun)
- 📜 JavaScript extraction & analysis (getJS, linkfinder)
- ☁️ Cloud asset enumeration (S3, Azure, GCP)
- 🚨 Subdomain takeover detection (subjack)
- 📧 OSINT & email harvesting (theHarvester)
- 📸 Screenshot gallery with HTML viewer
- 🔔 Discord notifications for real-time updates
- ⚙️ YAML-configurable pipelines
- 🆕 **5 Scan Modes**: wide, narrow, fast, osint, deep
- 🆕 **Screenshot Gallery**: Interactive HTML viewer
- 🆕 **48+ Tools** integrated

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Kali Linux / Ubuntu / Debian (recommended)
- Go 1.21+ (for installing recon tools)

### Installation

```bash
# Clone repository
git clone https://github.com/root-Manas/macaron.git
cd macaron

# Install Python dependencies
pip install rich pyyaml

# Make macaron executable and install globally
chmod +x macaron
sudo cp macaron /usr/local/bin/

# Install recon tools (optional - run as needed)
sudo ./install.sh
```

### Verify Installation

```bash
# Check version
macaron --version

# List installed tools
macaron -L
```

## 📖 Usage

### Quick Reference

| Command | Description |
|---------|-------------|
| `macaron -s target.com` | Wide scan (infrastructure recon) |
| `macaron -s target.com -f` | Fast scan (quick subdomain + probe) |
| `macaron -s target.com -n` | Narrow scan (app-focused) |
| `macaron -s target.com -m deep` | Deep comprehensive scan |
| `macaron -s target.com -m osint` | OSINT passive recon |
| `macaron -s target.com --resume` | Resume interrupted scan |
| `macaron -S` | Show status of all scanned domains |
| `macaron -R -d target` | Show results for a domain |
| `macaron -G -d target` | Generate screenshot gallery |
| `macaron -L` | List installed tools (48+) |
| `macaron -P` | Show pipeline config path |
| `macaron -E -o file.json` | Export results to JSON |

### Scanning Targets

```bash
# Wide mode - Infrastructure reconnaissance (default)
macaron -s example.com

# Fast mode - Quick subdomain enumeration + HTTP probe
macaron -s target.com -f

# Narrow mode - Application-focused (URLs, JS, crawling)
macaron -s https://app.example.com -n

# Deep mode - Comprehensive recon (bruteforce, permutation, all tools)
macaron -s target.com -m deep

# OSINT mode - Passive intelligence gathering
macaron -s target.com -m osint

# Scan multiple targets
macaron -s example.com test.com api.example.com

# Scan from file (one target per line)
macaron -F targets.txt

# Scan from stdin
cat targets.txt | macaron --stdin

# Disable proxychains wrapper
macaron -s target.com --no-proxy

# Resume an interrupted scan
macaron -s target.com --resume
```

### Viewing Results

```bash
# Show scan status for all domains
macaron -S

# Show all results for a domain
macaron -R -d example.com

# Show specific result types
macaron -R -d example.com -w subdomains
macaron -R -d example.com -w live
macaron -R -d example.com -w urls
macaron -R -d example.com -w ports
macaron -R -d example.com -w js
macaron -R -d example.com -w vulns

# Limit output
macaron -R -d example.com --limit 50

# Export to JSON
macaron -E -d example.com -o results.json
```

### Rate Limiting & Stealth

```bash
# Slow mode (10 requests/second)
macaron -s target.com --slow

# Custom rate limit
macaron -s target.com --rate 5

# With custom threads
macaron -s target.com --threads 10
```

### Tool Management

```bash
# List all tools and their status
macaron -L

# Show pipeline configuration path
macaron -P

# Install tools (requires sudo)
macaron -I
```

## 🛠️ Scan Modes

### WIDE Mode (Default) - Infrastructure Reconnaissance
Best for: Initial recon, mapping attack surface
```bash
macaron -s example.com
```

| Stage | Tools | Output |
|-------|-------|--------|
| Subdomain Discovery | subfinder, amass, assetfinder, findomain, crtsh | `subdomains.txt` |
| Subdomain Permutation | dnsgen | `subdomains.txt` |
| DNS Resolution | dnsx | `resolved.txt` |
| Port Scanning | naabu | `ports.txt` |
| HTTP Probing | httpx | `live_hosts.txt` |
| Web Fingerprinting | whatweb | `technologies.txt` |
| URL Discovery | gau, waybackurls, katana | `urls.txt` |
| Parameter Mining | paramspider | `parameters.txt` |
| JS Extraction | getJS, subjs | `js_files.txt` |
| Screenshots | gowitness | `screenshots/` |
| Subdomain Takeover | subjack | `takeovers.txt` |

### FAST Mode - Quick Wins
Best for: Quick assessment, time-limited testing
```bash
macaron -s target.com -f
```

| Stage | Tools | Output |
|-------|-------|--------|
| Quick Subdomains | subfinder, crtsh | `subdomains.txt` |
| HTTP Probe | httpx | `live_hosts.txt` |
| Quick URLs | gau | `urls.txt` |
| Screenshots | gowitness | `screenshots/` |

### NARROW Mode - Application-Focused
Best for: Single application testing, deep crawling
```bash
macaron -s https://app.example.com -n
```

| Stage | Tools | Output |
|-------|-------|--------|
| DNS Validation | dnsx | `resolved.txt` |
| Port Scan | naabu | `ports.txt` |
| HTTP Probing | httpx | `live_hosts.txt` |
| Web Fingerprinting | whatweb | `technologies.txt` |
| Deep Crawling | katana, hakrawler, gospider | `urls.txt` |
| Parameter Discovery | paramspider, arjun | `parameters.txt` |
| JS Analysis | getJS, linkfinder | `js_files.txt` |
| Content Discovery | ffuf | `content.txt` |
| Screenshots | gowitness | `screenshots/` |

### OSINT Mode - Passive Intelligence
Best for: Passive reconnaissance, no direct target interaction
```bash
macaron -s target.com -m osint
```

| Stage | Tools | Output |
|-------|-------|--------|
| Subdomain Discovery | subfinder, amass, crtsh | `subdomains.txt` |
| ASN Discovery | asnmap, amass intel | `asn_info.txt` |
| Email Harvesting | theHarvester | `emails.txt` |
| Shodan Recon | shodan | `shodan_data.txt` |
| Cloud Enumeration | cloud_enum | `cloud_assets.txt` |

### DEEP Mode - Comprehensive Scan
Best for: Thorough reconnaissance, time-flexible testing
```bash
macaron -s target.com -m deep
```

| Stage | Tools | Output |
|-------|-------|--------|
| Subdomain Discovery | subfinder, amass, assetfinder, findomain, crtsh | `subdomains.txt` |
| Subdomain Bruteforce | shuffledns | `subdomains.txt` |
| Subdomain Permutation | dnsgen, altdns | `subdomains.txt` |
| Full DNS Resolution | dnsx (all record types) | `resolved.txt` |
| Reverse DNS | hakrevdns | `reverse_dns.txt` |
| Full Port Scan | naabu (top 1000) | `ports.txt` |
| HTTP Probing | httpx (with favicon, JARM) | `live_hosts.txt` |
| Favicon Hashing | favfreak | `favicon_hashes.txt` |
| Web Fingerprinting | whatweb, webanalyze | `technologies.txt` |
| Deep Crawling | katana, gospider | `urls.txt` |
| URL Archives | gau, waybackurls | `urls.txt` |
| Parameter Discovery | paramspider, arjun | `parameters.txt` |
| API Discovery | kiterunner | `api_endpoints.txt` |
| JS Extraction | getJS, subjs, linkfinder | `js_files.txt` |
| Content Discovery | ffuf, feroxbuster | `content.txt` |
| Cloud Enumeration | cloud_enum, s3scanner | `cloud_assets.txt` |
| Subdomain Takeover | subjack, nuclei | `takeovers.txt` |
| Screenshots | gowitness | `screenshots/` |

## 📸 Screenshot Gallery

Macaron automatically generates an interactive HTML gallery from screenshots:

```bash
# Generate gallery for a domain
macaron -G -d example.com

# Gallery is also auto-generated after scans with screenshots
# Open in browser: ~/.macaron/data/example.com/gowitness/gallery.html
```

**Gallery Features:**
- 🖼️ Grid view of all screenshots
- 🔍 Search/filter by URL
- 📊 Filter by HTTP status code (2xx, 3xx, 4xx, 5xx)
- 🔎 Click to zoom
- 📱 Responsive design

## 🆕 Diff Tracking

Macaron tracks what's new since your last scan. After each scan:

```bash
# View diff report showing new assets
macaron -R -d example.com -w diff

# Output shows:
# [+] NEW SUBDOMAINS (5)
#     api2.example.com
#     staging.example.com
#     ...
# [+] NEW LIVE HOSTS (2)
#     https://api2.example.com
#     ...
```

The scan summary table also shows new counts:

```
╭─────────────────┬─────────┬─────╮
│ Metric          │   Total │ New │
├─────────────────┼─────────┼─────┤
│ Subdomains      │     150 │ +12 │
│ Live Hosts      │      45 │  +3 │
│ Vulnerabilities │       2 │  +1 │
╰─────────────────┴─────────┴─────╯
```

Files created:
- `.scan_history.json` - Previous scan data for comparison
- `diff_report.txt` - Human-readable diff report

## ⏸️ Resume Support (NEW in v2.2)

If a scan is interrupted (Ctrl+C, network issue, etc.), you can resume it:

```bash
# Interrupt a scan with Ctrl+C
# You'll see: "💾 State saved. Resume with --resume flag"

# Resume from where you left off
macaron -s target.com --resume
```

State is saved after each stage, so you won't lose progress on long scans.

## 📁 Data Storage

All scan data is stored in `~/.macaron/data/<domain>/`:

```
~/.macaron/
├── config/
│   └── pipeline.yaml      # ⚙️ EDIT THIS to customize scans!
├── data/
│   └── example.com/
│       ├── subdomains.txt  # Discovered subdomains
│       ├── live_hosts.txt  # Live HTTP hosts
│       ├── ports.txt       # Open ports
│       ├── urls.txt        # Discovered URLs
│       ├── js_files.txt    # JavaScript files
│       ├── vulns.json      # Nuclei findings
│       ├── diff_report.txt # New assets since last scan
│       └── .scan_history.json  # Previous scan data
└── state/
    └── <target>.state.json  # Resume data for interrupted scans
```

## ⚙️ Pipeline Configuration

The magic of Macaron is in `~/.macaron/config/pipeline.yaml`. Edit this file to:
- Change tool options and flags
- Add/remove tools from stages
- Create custom scan modes
- Adjust timeouts and rate limits

```bash
# Show pipeline config path
macaron -P

# Edit the pipeline
nano ~/.macaron/config/pipeline.yaml
```

### Example: Customizing Subfinder

```yaml
tools:
  subfinder:
    cmd: "subfinder"
    args: "-d {target} -all -recursive -o {output}"
    timeout: 600
```

### Example: Adding a Custom Mode

```yaml
modes:
  stealth:
    description: "Slow and quiet scanning"
    stages:
      - name: "Passive Subdomains"
        tools: ["subfinder"]
      - name: "Slow HTTP Probe"
        tools: ["httpx"]
        input: "subdomains.txt"
        output: "live.txt"
```

## 🔧 Tool Installation

### Quick Install (All Tools)

```bash
sudo ./install.sh
```

### Manual Installation

```bash
# Go tools (requires Go 1.21+)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest

# Update nuclei templates
nuclei -update-templates
```

### Check Tool Status

```bash
macaron -L
```

Output:
```
╭─────────────┬──────────────┬────────╮
│ Category    │ Tool         │ Status │
├─────────────┼──────────────┼────────┤
│ Subdomain   │ subfinder    │   ✓    │
│ Subdomain   │ amass        │   ✓    │
│ HTTP        │ httpx        │   ✓    │
│ Ports       │ naabu        │   ✓    │
│ Vulns       │ nuclei       │   ✓    │
╰─────────────┴──────────────┴────────╯
```

## 🔔 Discord Notifications

Set up Discord webhook for real-time scan updates:

```bash
# Set webhook URL
macaron --webhook "https://discord.com/api/webhooks/..."

# Test the webhook
macaron --test
```

## 📊 Example Workflow

```bash
# 1. Quick recon on new target
macaron -s target.com -f

# 2. Check what we found
macaron -R -d target.com

# 3. Deep scan on interesting subdomains
macaron -s api.target.com -n

# 4. Export everything for manual testing
macaron -E -d target.com -o target_recon.json

# 5. Check overall status
macaron -S
```

## 🎯 Pro Tips

1. **Start with Fast Mode** - Get quick wins first
   ```bash
   macaron -s target.com -f
   ```

2. **Use Narrow Mode for Apps** - When you have a specific application
   ```bash
   macaron -s https://app.target.com -n
   ```

3. **Customize the Pipeline** - Edit `~/.macaron/config/pipeline.yaml` to add your favorite tools

4. **Use Rate Limiting** - Be nice to targets
   ```bash
   macaron -s target.com --slow
   ```

5. **Check Results Often** - Data accumulates across scans
   ```bash
   macaron -R -d target.com -w urls | grep api
   ```

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

MIT License - see LICENSE file for details

## ⚠️ Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before scanning targets. The authors are not responsible for misuse.


## 📞 Support

- GitHub Issues: [Report bugs](https://github.com/root-Manas/macaron/issues)
- Pull Requests: [Contribute](https://github.com/root-Manas/macaron/pulls)

---

**Version**: 2.3.0  
**Status**: Production Ready  
**Last Updated**: 2026-01-06

