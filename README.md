# Macaron v2.1 - Security Reconnaissance Platform

**A powerful CLI-based security reconnaissance and asset discovery platform**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🎯 Overview

Macaron is a comprehensive security reconnaissance platform designed for bug bounty hunters and security researchers. It automates the discovery and analysis of attack surfaces through intelligent tool orchestration and data correlation.

**Key Features**:
- 🔍 Automated subdomain discovery with 8+ tools
- 🌐 HTTP probing and technology detection
- 🔓 Port scanning and service enumeration
- 🎯 Vulnerability scanning with Nuclei integration
- 📊 PostgreSQL database for persistent storage
- 🔔 Discord notifications for real-time updates
- ⏰ Scheduled scans with cron support
- 📦 Modular architecture for easy extension

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- PostgreSQL database
- Reconnaissance tools (subfinder, amass, httpx, nuclei, etc.)

### Installation

```bash
# Clone repository
git clone https://github.com/root-Manas/macaron.git
cd macaron

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install package
pip install -e .

# Configure environment
cp .env.example .env
nano .env  # Edit with your settings
```

### Required Environment Variables

```bash
# Database (Required)
DATABASE_URL=postgresql://user:password@localhost/recon_db

# Security
SECRET_KEY=your-secret-key-here

# Discord Notifications (Optional)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...

# API Keys (Optional)
SHODAN_API_KEY=your-key
VIRUSTOTAL_API_KEY=your-key
CHAOS_API_KEY=your-key
```

### Database Setup

```bash
# Create database
createdb recon_db

# Run migrations
alembic upgrade head
```

## 📖 Usage

### Basic Scanning

```bash
# Scan a single target (WIDE mode - infrastructure focus)
python recon.py scan -t example.com -m wide

# Scan multiple targets
python recon.py scan -t example.com test.com -m wide

# NARROW mode (application-specific)
python recon.py scan -t https://app.example.com -m narrow

# Resume interrupted scan
python recon.py scan -r
```

### Managing Targets

```bash
# Add target
python recon.py add target example.com

# Add from file
python recon.py add targets -f targets.txt

# List all targets
python recon.py list targets

# List by program
python recon.py list targets -p "Bug Bounty Program"
```

### Exporting Results

```bash
# Export to JSON
python recon.py export -f json -o results.json

# Export to CSV
python recon.py export -f csv -o results.csv

# Export specific target
python recon.py export -t example.com -f json
```

### Scheduling

```bash
# Add scheduled scan (daily at 2 AM)
python recon.py schedule add -t example.com -c "0 2 * * *"

# List scheduled scans
python recon.py schedule list

# Remove scheduled scan
python recon.py schedule remove <id>
```

## 🛠️ Scan Modes

### WIDE Mode (Infrastructure Reconnaissance)
Comprehensive infrastructure mapping:
1. **Subdomain Discovery**: subfinder, amass, assetfinder, findomain, crt.sh
2. **DNS Resolution**: puredns with custom resolvers
3. **HTTP Probing**: httpx for live host detection
4. **Port Scanning**: naabu for open port discovery
5. **Technology Detection**: httpx, wappalyzer
6. **Screenshot Capture**: gowitness
7. **Vulnerability Scanning**: nuclei with custom templates

### NARROW Mode (Application-Specific)
Focused application testing:
1. **URL Discovery**: katana, waybackurls, gau
2. **JavaScript Analysis**: subjs, linkfinder
3. **Parameter Discovery**: arjun, paramspider
4. **Vulnerability Scanning**: nuclei (web-focused templates)
5. **API Discovery**: endpoint enumeration

## 📁 Directory Structure

```
security-recon-platform/
├── backend/
│   ├── scan_engine.py      # Core scanning orchestration
│   ├── database.py          # SQLAlchemy models
│   ├── tools.py             # Tool execution and management
│   ├── notifier.py          # Discord notifications
│   └── scheduler.py         # Cron job management
├── shared/
│   ├── types.py             # Data structures
│   ├── utils.py             # Utility functions
│   └── exceptions.py        # Custom exceptions
├── config/
│   ├── config.yaml          # Main configuration
│   ├── pipeline.yaml        # Tool pipeline definitions
│   └── resolvers.txt        # DNS resolvers
├── recon.py                 # CLI entry point
└── .env                     # Environment variables
```

## ⚙️ Configuration

Edit `config/config.yaml` for detailed configuration:

```yaml
general:
  data_dir: "./data"
  logs_dir: "./logs"
  max_concurrent_scans: 5

discord:
  enabled: true
  notify_on:
    - scan_start
    - scan_complete
    - new_vulnerability

modules:
  subdomain_discovery:
    enabled: true
    tools:
      - subfinder
      - amass
      - assetfinder
```

## 🔧 Tool Installation

Install required reconnaissance tools:

```bash
# Run installation script
./install.sh

# Or install individually
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# ... etc
```

## 📊 Database Schema

- **targets**: Target domains/IPs
- **scans**: Scan execution records
- **assets**: Discovered subdomains, IPs, URLs
- **endpoints**: HTTP endpoints with metadata
- **vulnerabilities**: Nuclei findings
- **cron_jobs**: Scheduled scan configurations

## 🔔 Discord Notifications

Configure Discord webhook for real-time updates:
- Scan start/completion
- New subdomain discoveries
- Vulnerability findings
- Error alerts

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

MIT License - see LICENSE file for details

## ⚠️ Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before scanning targets.

## 🙏 Credits

Built with:
- [ProjectDiscovery](https://projectdiscovery.io/) tools
- [SQLAlchemy](https://www.sqlalchemy.org/)
- [Rich](https://rich.readthedocs.io/)
- [Typer](https://typer.tiangolo.com/)

## 📞 Support

- GitHub Issues: [Report bugs](https://github.com/root-Manas/macaron/issues)
- Documentation: [Wiki](https://github.com/root-Manas/macaron/wiki)

---

**Version**: 2.1.0  
**Status**: Production Ready (CLI)  
**Last Updated**: 2026-01-05
