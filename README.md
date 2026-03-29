# macaronV2

`macaronV2` is a full Go rewrite of the original tool with a faster pipeline, SQLite-backed storage, and a web dashboard for indexed scan review.

## What is new

- Stable Go runtime (`go 1.22+`)
- Stage-based concurrent pipeline (`subdomains,http,ports,urls,vulns`)
- SQLite database for structured storage and fast queries
- Per-target storage folders under one root (`./storage/<target>/`)
- Security-style dashboard with scan search, details, and global heat map
- API key config support for enrichment sources (currently `securitytrails`)

## Install

### WSL / Linux (recommended)

```bash
git clone https://github.com/root-Manas/macaron.git
cd macaron
chmod +x install.sh
./install.sh
source ~/.bashrc
macaron --version
```

`install.sh` builds and installs to `~/.local/bin/macaron` and updates your PATH.

### Manual build

```bash
go mod tidy
go build -o macaron ./cmd/macaron
./macaron --version
```

## Storage model

Default storage root is repo-local `./storage` (can be overridden with `--storage`).

```text
storage/
  macaron.db                # SQLite index/query database
  config.yaml               # API keys and local config
  <target>/
    <scan-id>.json          # mirrored JSON artifact
    latest.txt
```

## Usage

### Run scans

```bash
# Full default pipeline
macaron -s example.com

# Fast mode
macaron -s example.com -f

# Multiple targets
macaron -s example.com test.com

# File input
macaron -F targets.txt

# Custom stage workflow
macaron -s example.com --stages subdomains,http,urls
```

### Setup tools (new)

```bash
# View installed/missing toolchain
macaron --setup
# also works:
macaron -setup

# Install missing supported tools (Linux)
macaron --install-tools
```

### Results and export

```bash
macaron -S
macaron -R -d example.com -w live
macaron -R -d example.com -w vulns --limit 100
macaron -E -o results.json
```

### Dashboard

```bash
macaron --serve --addr 127.0.0.1:8088
# open http://127.0.0.1:8088
```

### API key enrichment

```bash
# Set API keys (repeatable)
macaron --set-api securitytrails=YOUR_KEY

# Show masked keys
macaron --show-api

# Unset key
macaron --set-api securitytrails=
```

## CLI reference

```text
SCANNING:
  -s, --scan TARGETS        Scan one or more targets
  -F, --file FILE           Read targets from file
  --stdin                   Read targets from stdin
  -m, --mode MODE           wide|narrow|fast|deep|osint
  -f, --fast                Shortcut for mode fast
  -n, --narrow              Shortcut for mode narrow
  --stages LIST             subdomains,http,ports,urls,vulns
  --rate N                  Request rate hint
  --threads N               Worker threads

RESULTS:
  -S, --status              Show scan summaries
  -R, --results             Show scan details
  -d, --domain DOMAIN       Filter by domain
  --id SCAN_ID              Fetch specific scan by ID
  -w, --what TYPE           all|subdomains|live|ports|urls|js|vulns
  --limit N                 Limit printed results
  -E, --export              Export JSON
  -o, --output FILE         Export file path

WEB:
  --serve                   Start dashboard server
  --addr HOST:PORT          Bind address

CONFIG:
  --storage DIR             Storage root (default ./storage)
  --set-api k=v             Save API key to storage config
  --show-api                Show masked configured keys

OTHER:
  -L, --list-tools          Show optional tool availability
  --setup                   Setup view with tool status
  --install-tools           Install missing supported tools (Linux)
  -C, --config              Show storage paths
  --version                 Show version
```

## Pipeline notes

The Go pipeline is stage-driven and optimized around native collectors + concurrency. Optional external binaries (e.g. `subfinder`, `assetfinder`, `findomain`, `nuclei`) are used when present; otherwise the scan still runs with native stages.

## Security and authorization

Use only on assets you own or are explicitly authorized to test. Do not use for unauthorized scanning or bypass attempts.
