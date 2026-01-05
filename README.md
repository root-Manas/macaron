# Macaron v2.1 🍪

A YAML-configurable security reconnaissance CLI. Customize every tool command, create custom pipelines, and chain 30+ recon tools with beautiful progress UI.

```
███╗   ███╗ █████╗  ██████╗ █████╗ ██████╗  ██████╗ ███╗   ██╗
████╗ ████║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
██╔████╔██║███████║██║     ███████║██████╔╝██║   ██║██╔██╗ ██║
██║╚██╔╝██║██╔══██║██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║
██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                  v2.1 - YAML-Configured Recon
```

## ✨ What's New in v2.1

- **📝 YAML Pipeline Config** - Edit `~/.macaron/config/pipeline.yaml` to customize everything
- **🎨 Beautiful UI** - Progress bars, spinners, colored output with Rich library
- **⚡ Short CLI Flags** - `-s` scan, `-S` status, `-R` results, `-L` tools, `-P` pipeline
- **🔧 Custom Modes** - Create your own scan pipelines in YAML
- **📊 Live Progress** - See each tool running with progress tracking

## 🚀 Quick Start

```bash
# Install
chmod +x macaron && sudo cp macaron /usr/local/bin/
pip install rich pyyaml  # Required libraries
sudo macaron -I          # Install recon tools

# Scan!
macaron -s example.com           # Wide scan (default)
macaron -s app.com -n            # Narrow scan (app-focused)
macaron -s target.com -f         # Fast scan (quick wins)
macaron -s target.com -m custom  # Custom mode from YAML
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
| `-P` | `--pipeline` | Show pipeline.yaml path |
| `-C` | `--config` | Show configuration |

### Scan Options

| Flag | Description |
|------|-------------|
| `-m MODE` | Use scan mode from YAML (wide/narrow/fast/custom) |
| `-n` | Narrow mode (app-focused) |
| `-f` | Fast mode (minimal tools) |
| `-F FILE` | Targets from file |
| `--stdin` | Read from stdin |
| `--slow` | Slow mode (10 req/s) |
| `--no-proxy` | Disable proxychains |
| `-q` | Quiet mode |

## ⚙️ YAML Configuration

All tool commands and pipelines are defined in `~/.macaron/config/pipeline.yaml`:

```bash
# Show config path
macaron -P

# Edit the config
nano ~/.macaron/config/pipeline.yaml
```

### Customize Tool Commands

```yaml
tools:
  subfinder:
    cmd: "subfinder -d {target} -silent -all -t {threads}"
    timeout: 600
    
  # Change options as needed:
  nuclei:
    cmd: "nuclei -l {input_file} -o {output_file} -severity critical,high -rl 50"
    timeout: 7200
```

### Create Custom Pipelines

```yaml
pipelines:
  # Your custom quick-enum mode
  quick_enum:
    description: "Quick subdomain enumeration only"
    stages:
      - name: "Subdomain Discovery"
        emoji: "🔍"
        tools: [subfinder, crtsh]
        input_from: target
        output_to: subdomains
        enabled: true
      
      - name: "HTTP Probing"
        emoji: "🌐"
        tools: [httpx]
        input_from: subdomains
        output_to: live_hosts
        enabled: true
```

Then run: `macaron -s target.com -m quick_enum`

### Available Placeholders

| Placeholder | Description |
|-------------|-------------|
| `{target}` | The target domain |
| `{input_file}` | Temp file with input list |
| `{output_file}` | Output file path |
| `{output_dir}` | Output directory |
| `{threads}` | Thread count |
| `{rate}` | Rate limit |

## 📋 Built-in Scan Modes

### 🔍 WIDE Mode (Default)
```
1. Subdomain Discovery  →  subfinder, amass, assetfinder, findomain, crt.sh
2. DNS Resolution       →  dnsx
3. Port Scanning        →  naabu (top 1000)
4. HTTP Probing         →  httpx (tech-detect, CDN)
5. URL Discovery        →  gau, waybackurls, katana
6. JS Analysis          →  getJS
7. Screenshots          →  gowitness
8. Vuln Scanning        →  nuclei
```

### 🎯 NARROW Mode (-n)
```
1. DNS Validation       →  dnsx
2. Light Port Scan      →  naabu (web ports)
3. HTTP Probing         →  httpx
4. Deep Crawling        →  katana, hakrawler
5. URL Archives         →  gau, waybackurls
6. JS Analysis          →  getJS
7. Content Discovery    →  ffuf
8. Screenshots          →  gowitness
9. Vuln Scanning        →  nuclei
```

### ⚡ FAST Mode (-f)
```
1. Quick Subdomains     →  subfinder, crt.sh
2. HTTP Probing         →  httpx
3. Quick Vuln Scan      →  nuclei (critical+high)
```

## 💻 Examples

```bash
# Wide infrastructure scan
macaron -s hackerone.com

# Narrow app-focused scan
macaron -s https://api.example.com -n

# Fast scan for quick wins
macaron -s target.com -f

# Custom pipeline
macaron -s target.com -m quick_enum

# Multiple targets
macaron -s -F scope.txt

# Slow and stealthy
macaron -s target.com --slow

# View results
macaron -R -d example.com -w vulns

# Export
macaron -E -o report.json
```

## 📁 Directory Structure

```
~/.macaron/
├── config/
│   ├── config.json       # Discord webhook, etc.
│   └── pipeline.yaml     # ⭐ Tool & pipeline config
├── data/
│   └── <target>/
│       ├── subdomains.txt
│       ├── live_hosts.txt
│       ├── urls.txt
│       ├── nuclei.json
│       └── ...
└── wordlists/
    └── common.txt
```

## 📱 Discord Notifications

```bash
macaron --webhook "https://discord.com/api/webhooks/..." --test
```

## License

MIT - Use responsibly for authorized testing only.
