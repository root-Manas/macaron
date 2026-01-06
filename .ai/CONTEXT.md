# Macaron - AI Context File

> Read this file at the start of every session to understand the project.

## What is Macaron?

Macaron is a **pure reconnaissance platform** for bug bounty hunters. It orchestrates 48+ security tools to gather data about targets. It does NOT do vulnerability scanning - only recon.

**Version**: 2.4.0  
**Language**: Python 3.9+  
**Platform**: Linux (Kali/Ubuntu/Debian)  
**Author**: root-Manas

## Project Structure

```
macaron/
├── macaron                 # Main script (single file, ~2400 lines)
├── config/
│   ├── config.yaml         # Main config (discord, proxy, rate limits)
│   └── pipeline.yaml       # Tool definitions & scan modes
├── tests/
│   └── test_cli.py         # 14 CLI tests
├── .github/workflows/
│   └── ci.yml              # GitHub Actions CI
├── install.sh              # Installation script
├── requirements.txt        # Python deps (rich, pyyaml)
├── setup.py
└── README.md
```

## Architecture

### Single-File Design
The entire tool is in one file (`macaron`) for easy installation:
```bash
sudo cp macaron /usr/local/bin/
```

### Key Classes/Components

| Component | Purpose |
|-----------|---------|
| `ToolRunner` | Executes tools from YAML config |
| `ScanEngine` | Orchestrates scan pipelines |
| `StateManager` | Saves/restores scan state for resume |
| `DiffTracker` | Tracks new assets between scans |
| `ScreenshotGallery` | Generates HTML gallery from screenshots |
| `DiscordNotifier` | Sends Discord webhook notifications |

### Data Flow

```
Target → Subdomain Discovery → DNS Resolution → Port Scan → HTTP Probe → URL Mining → Screenshots → Gallery
```

### Config System

1. **pipeline.yaml**: Defines tools and scan modes
   - Tool commands with placeholders: `{target}`, `{input_file}`, `{output_dir}`
   - 5 scan modes: wide, narrow, fast, osint, deep
   - Each mode has stages with tools

2. **config.yaml**: Runtime settings
   - Discord webhook
   - Proxy settings
   - Rate limits

## CLI Flags

```
SCANNING:
  -s TARGET         Scan target(s)
  -F FILE           From file
  --stdin           From stdin
  -m MODE           Mode: wide|narrow|fast|osint|deep
  -f                Fast mode
  -n                Narrow mode
  --resume          Resume interrupted scan
  --slow            10 req/s
  --rate N          Custom rate
  --threads N       Threads
  -q                Quiet

RESULTS:
  -S                Status
  -R                Results (use -d)
  -G                Gallery (use -d)
  -E                Export JSON
  -d DOMAIN         Filter domain
  -w TYPE           subdomains|live|ports|urls|js|diff
  -o FILE           Output file

CONFIG:
  -C                Show config
  -P                Pipeline path
  --webhook URL     Set Discord
  --test            Test webhook

TOOLS:
  -L                List tools
  -I                Install tools (sudo)
  -U                Update macaron
```

## 48 Tools by Category

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
| Parameters | paramspider, arjun, x8 |
| API | kiterunner |
| JS | getJS, subjs, linkfinder |
| Content | ffuf, feroxbuster |
| Cloud | cloud_enum, s3scanner |
| Takeover | subjack |
| OSINT | theHarvester, emailfinder, shodan |
| Screenshots | gowitness, eyewitness |

## 5 Scan Modes

| Mode | Command | Use Case |
|------|---------|----------|
| wide | `macaron -s target` | Full infrastructure recon |
| fast | `macaron -s target -f` | Quick subdomain + probe |
| narrow | `macaron -s target -n` | Single app, deep crawl |
| osint | `macaron -s target -m osint` | Passive, no contact |
| deep | `macaron -s target -m deep` | Everything + bruteforce |

## Output Files

All in `~/.macaron/data/<domain>/`:
- `subdomains.txt`, `live_hosts.txt`, `ports.txt`
- `urls.txt`, `js_files.txt`, `parameters.txt`
- `technologies.txt`, `takeovers.txt`
- `gowitness/` (screenshots + gallery.html)
- `diff_report.txt`, `summary.json`

## Testing

```bash
# Run all tests
pytest tests/ -v

# Tests must pass before PR merge (CI enforces this)
```

## Common Tasks

### Add a new tool
1. Add to `pipeline.yaml` under `tools:`
2. Add to appropriate scan mode stages
3. Add to `-L` list in `cmd_tools()`
4. Add install command in `cmd_install()`

### Add a new scan mode
1. Add to `pipeline.yaml` under `pipelines:`
2. Define stages with tools
3. Update help text in `main()`

### Fix a bug
1. Create branch: `git checkout -b fix/description`
2. Make changes
3. Run tests: `pytest tests/ -v`
4. Commit, push, create PR
5. Wait for CI to pass
6. Merge

## Important Notes

1. **Pure Recon Only** - No vulnerability scanning in default pipelines
2. **Linux Only** - Uses Linux tools (apt, go, bash)
3. **Single File** - Keep everything in `macaron` for easy install
4. **YAML-Driven** - Tools defined in pipeline.yaml, not hardcoded
5. **Rich Console** - Uses `force_terminal=True, stderr=True` for CI compatibility

## Version History

| Version | Changes |
|---------|---------|
| 2.4.0 | Full 48-tool installer |
| 2.3.0 | 5 scan modes, screenshot gallery, 48 tools |
| 2.2.0 | Diff tracking, resume support, Discord |
| 2.1.0 | YAML pipeline config |
| 2.0.0 | Complete rewrite |

## Links

- GitHub: https://github.com/root-Manas/macaron
- Issues: https://github.com/root-Manas/macaron/issues

---
*Last updated: 2026-01-06*
