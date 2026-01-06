# Macaron

```
███╗   ███╗ █████╗  ██████╗ █████╗ ██████╗  ██████╗ ███╗   ██╗
████╗ ████║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
██╔████╔██║███████║██║     ███████║██████╔╝██║   ██║██╔██╗ ██║
██║╚██╔╝██║██╔══██║██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║
██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
```

**Security reconnaissance platform for bug bounty hunters. 47 tools. 5 scan modes. Pure recon.**

## Installation

```bash
git clone https://github.com/root-Manas/macaron.git
cd macaron
pip install rich pyyaml
chmod +x macaron
sudo cp macaron /usr/local/bin/

# Install recon tools
sudo macaron -I
```

## Commands

```
macaron [OPTIONS]

SCANNING:
  -s, --scan TARGET       Scan target(s)
  -F, --file FILE         Scan targets from file
  --stdin                 Read targets from stdin
  -m, --mode MODE         Scan mode: wide|narrow|fast|osint|deep
  -f, --fast              Shortcut for -m fast
  -n, --narrow            Shortcut for -m narrow
  --resume                Resume interrupted scan
  --no-proxy              Disable proxychains
  --slow                  Rate limit to 10 req/s
  --rate N                Custom rate limit (req/s)
  --threads N             Number of threads
  -q, --quiet             Suppress output

RESULTS:
  -S, --status            Show scan status for all domains
  -R, --results           Show results (use with -d)
  -G, --gallery           Generate screenshot gallery (use with -d)
  -E, --export            Export results to JSON
  -d, --domain DOMAIN     Filter by domain
  -w, --what TYPE         Filter: all|subdomains|live|ports|urls|js|vulns|diff
  --limit N               Limit output (default: 50)
  -o, --output FILE       Output file for export

CONFIGURATION:
  -C, --config            Show config file paths
  --show                  Show current config
  -P, --pipeline          Show pipeline.yaml path
  --webhook URL           Set Discord webhook
  --test                  Test Discord webhook

TOOLS:
  -L, --list-tools        List all 47 tools and install status
  -I, --install           Install recon tools (requires sudo)
  -U, --update            Update macaron to latest version

OTHER:
  -v, --verbose           Verbose output
  -h, --help              Show help
  --version               Show version
```

## Usage Examples

### Basic Scanning

```bash
# Default wide scan
macaron -s example.com

# Fast scan (subdomains + http probe only)
macaron -s example.com -f

# Narrow scan (deep crawling, single app)
macaron -s https://app.example.com -n

# OSINT mode (passive, no direct contact)
macaron -s example.com -m osint

# Deep scan (everything, bruteforce, permutations)
macaron -s example.com -m deep
```

### Multiple Targets

```bash
# Multiple domains
macaron -s example.com test.com api.example.com

# From file
macaron -F targets.txt

# From stdin
cat targets.txt | macaron --stdin
echo "example.com" | macaron --stdin
```

### Rate Limiting

```bash
# Slow mode (10 req/s)
macaron -s example.com --slow

# Custom rate
macaron -s example.com --rate 5 --threads 3

# With proxy disabled
macaron -s example.com --no-proxy --rate 20
```

### Resume Interrupted Scans

```bash
# Start scan, interrupt with Ctrl+C
macaron -s example.com
# ^C (interrupted)

# Resume later
macaron -s example.com --resume
```

### Viewing Results

```bash
# Status of all scanned domains
macaron -S

# All results for a domain
macaron -R -d example.com

# Specific result types
macaron -R -d example.com -w subdomains
macaron -R -d example.com -w live
macaron -R -d example.com -w urls
macaron -R -d example.com -w ports
macaron -R -d example.com -w js
macaron -R -d example.com -w diff

# Limit output
macaron -R -d example.com -w urls --limit 100

# Quiet mode (no banners)
macaron -R -d example.com -q
```

### Screenshot Gallery

```bash
# Generate HTML gallery
macaron -G -d example.com

# Open in browser
xdg-open ~/.macaron/data/example.com/gowitness/gallery.html
```

### Export

```bash
# Export to JSON
macaron -E -o results.json

# Export specific domain
macaron -E -d example.com -o example.json
```

### Configuration

```bash
# Show config paths
macaron -C

# Show current config
macaron -C --show

# Show pipeline config path
macaron -P

# Edit pipeline (customize tools, modes)
nano ~/.macaron/config/pipeline.yaml
```

### Discord Notifications

```bash
# Set webhook
macaron --webhook "https://discord.com/api/webhooks/xxx/yyy"

# Test it
macaron --webhook "https://discord.com/api/webhooks/xxx/yyy" --test
```

### Tool Management

```bash
# List all tools
macaron -L

# Install tools (requires sudo)
sudo macaron -I

# Update macaron
macaron -U
# or with sudo for system install
sudo macaron -U
```

## Scan Modes

| Mode | Flag | Description |
|------|------|-------------|
| **wide** | `-s target` | Full infrastructure recon (default) |
| **fast** | `-f` | Quick subdomain + HTTP probe |
| **narrow** | `-n` | Deep crawling, single application |
| **osint** | `-m osint` | Passive recon, no direct contact |
| **deep** | `-m deep` | Comprehensive with bruteforce |

### Wide Mode (Default)
```bash
macaron -s example.com
```
Runs: subfinder, amass, assetfinder, findomain, crtsh → dnsgen → dnsx → naabu → httpx → whatweb → gau, waybackurls, katana → paramspider → getJS, subjs → gowitness → subjack

### Fast Mode
```bash
macaron -s example.com -f
```
Runs: subfinder, crtsh → httpx → gau → gowitness

### Narrow Mode
```bash
macaron -s https://app.example.com -n
```
Runs: dnsx → naabu → httpx → whatweb → katana, hakrawler, gospider → paramspider, arjun → getJS, linkfinder → ffuf → gowitness

### OSINT Mode
```bash
macaron -s example.com -m osint
```
Runs: subfinder, amass, crtsh → asnmap, amass intel → theHarvester → shodan → cloud_enum

### Deep Mode
```bash
macaron -s example.com -m deep
```
Runs: All 18 stages including bruteforce, permutation, full port scan, API discovery, cloud enumeration

## Tools (47)

| Category | Tools |
|----------|-------|
| Subdomain | subfinder, amass, assetfinder, findomain, github-subdomains |
| Permutation | altdns, dnsgen, shuffledns, puredns |
| DNS | dnsx, massdns, dnsrecon, hakrevdns |
| ASN/IP | asnmap, mapcidr |
| Ports | naabu, masscan, nmap |
| HTTP | httpx, httprobe |
| Fingerprint | whatweb, webanalyze, favfreak |
| URLs | gau, waybackurls, katana, hakrawler, gospider |
| Parameters | paramspider, arjun |
| API | kiterunner |
| JS | getJS, subjs, linkfinder |
| Content | ffuf, feroxbuster |
| Cloud | cloud_enum, s3scanner |
| Takeover | subjack |
| OSINT | theHarvester, emailfinder, shodan |
| Screenshots | gowitness, eyewitness |
| Utils | proxychains4, jq, curl |

## Output Files

All data stored in `~/.macaron/data/<domain>/`:

```
subdomains.txt      # Discovered subdomains
live_hosts.txt      # Live HTTP hosts  
ports.txt           # Open ports
urls.txt            # Discovered URLs
js_files.txt        # JavaScript files
parameters.txt      # URL parameters
technologies.txt    # Tech fingerprints
takeovers.txt       # Subdomain takeover candidates
summary.json        # Scan summary
diff_report.txt     # New assets since last scan
gowitness/          # Screenshots
  ├── *.png
  └── gallery.html  # Interactive gallery
```

## Configuration Files

```
~/.macaron/
├── config/
│   ├── config.yaml      # Main config (API keys, discord, rate limits)
│   └── pipeline.yaml    # Tool definitions & scan modes
├── data/                # Scan results
├── state/               # Resume state files
├── logs/                # Logs
└── wordlists/           # Wordlists for fuzzing
```

### Customize Pipeline

Edit `~/.macaron/config/pipeline.yaml` to:
- Modify tool commands
- Add/remove tools from stages
- Create custom scan modes
- Adjust timeouts

```bash
macaron -P  # Shows path
nano ~/.macaron/config/pipeline.yaml
```

## Common Workflows

### New Target Recon
```bash
macaron -s target.com -f          # Quick scan first
macaron -R -d target.com          # Check results
macaron -s target.com             # Full wide scan
macaron -G -d target.com          # Generate gallery
```

### Continuous Monitoring
```bash
macaron -s target.com             # Initial scan
# ... wait some time ...
macaron -s target.com             # Rescan
macaron -R -d target.com -w diff  # See what's new
```

### App-Focused Testing
```bash
macaron -s https://app.target.com -n   # Deep crawl
macaron -R -d app.target.com -w urls   # Check URLs
macaron -R -d app.target.com -w js     # Check JS files
```

### Stealth Scanning
```bash
macaron -s target.com --slow --no-proxy -m osint
```

### Export for Tools
```bash
# Get subdomains for other tools
macaron -R -d target.com -w subdomains -q > subs.txt

# Get live hosts
macaron -R -d target.com -w live -q > live.txt
```

## License

MIT

## Disclaimer

For authorized security testing only. Always obtain permission before scanning.

---
**v2.4.1** | [GitHub](https://github.com/root-Manas/macaron)
