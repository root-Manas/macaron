# macaronV2

Fast reconnaissance workflow in Go with SQLite-backed persistence and an operator-focused dashboard.

```
  ╔╦╗╔═╗╔═╗╔═╗╦═╗╔═╗╔╗╔
  ║║║╠═╣║  ╠═╣╠╦╝║ ║║║║
  ╩ ╩╩ ╩╚═╝╩ ╩╩╚═╚═╝╝╚╝

  Fast Recon Workflow  v3.0.0
  github.com/root-Manas/macaron
  ────────────────────────────────────────
```

## The Model

`macaronV2` is designed around one simple loop:

1. `setup` toolchain and keys
2. `scan` targets with an explicit profile
3. `status/results` to triage findings
4. `serve` to inspect everything in one dashboard
5. `export` to share/report

## Quick Start

```bash
git clone https://github.com/root-Manas/macaron.git
cd macaron
chmod +x install.sh
./install.sh
source ~/.bashrc

macaron setup
macaron scan example.com -prf balanced
macaron status
macaron serve
```

## Core Commands

```
USAGE
  macaron scan example.com
  macaron status
  macaron results -dom example.com -wht live
  macaron serve -adr 127.0.0.1:8088
  macaron setup
  macaron export -out results.json

SCAN FLAGS
  -scn TARGET   Scan one or more targets (repeatable)
  -fil FILE     Read targets from file
  -inp          Read targets from stdin
  -mod MODE     Scan mode: wide|narrow|fast|deep|osint
  -stg LIST     Stages: subdomains,http,ports,urls,vulns
  -prf NAME     Profile: passive|balanced|aggressive
  -rte N        Request rate hint (default: 150)
  -thr N        Worker threads (default: 30)

OUTPUT FLAGS
  -sts          Show recent scan summaries
  -res          Show scan results
  -dom DOMAIN   Filter by domain
  -wht TYPE     Result view: all|subdomains|live|ports|urls|js|vulns
  -lim N        Output limit (default: 50)
  -exp          Export results to JSON
  -qut          Quiet mode (suppress banner and progress)

API KEYS
  -sak k=v      Set API key (e.g. -sak securitytrails=KEY)
  -shk          Show masked API keys

DASHBOARD
  -srv          Start browser dashboard
  -adr ADDR     Bind address (default: 127.0.0.1:8088)

TOOLS & CONFIG
  -stp          Show tool installation status
  -ins          Install missing supported tools (Linux)
  -lst          List external tool availability
  -str DIR      Custom storage root (default: ./storage)
  -nc           Disable color output
  -ver          Show version
```

## Profiles

| Profile     | Description                                        |
|-------------|----------------------------------------------------|
| `passive`   | Low-noise, low-rate, mostly passive collection     |
| `balanced`  | Default practical workflow (recommended)           |
| `aggressive`| High-throughput for authorized deep testing only   |

## CLI UX

macaron follows the same UX patterns as ProjectDiscovery tools (nuclei, httpx, subfinder):

- **Colored log levels**: `[INF]`, `[WRN]`, `[ERR]`, `[OK]` with distinct colors
- **Live progress**: Braille-spinner with stage and elapsed time during scans
- **Colored tables**: Vulns highlighted in red, live hosts in green
- **Compact flags**: Short (`-scn`, `-mod`, `-prf`) with full-word aliases also accepted
- **NO_COLOR support**: Respects the `NO_COLOR` environment variable
- **Quiet mode**: `-qut` suppresses banner and progress for scripted use

## Storage

Default storage root: `./storage`

```text
storage/
  macaron.db
  config.yaml
  <target>/
    <scan-id>.json
    latest.txt
```

## Setup & API Keys

```bash
macaron setup
macaron -ins
macaron -sak securitytrails=YOUR_KEY
macaron -shk
```

## Stage Control

```bash
macaron scan example.com -stg subdomains,http,urls
```

Available stages: `subdomains`, `http`, `ports`, `urls`, `vulns`

## Dashboard

```bash
macaron serve
# or with custom address:
macaron serve -adr 127.0.0.1:8088
```

Open `http://127.0.0.1:8088` — includes scan list with mode filters, health badges, URL yield trend, and geo map.

## Release

```bash
git tag v3.0.1
git push origin v3.0.1
```

Tagged releases build and publish binaries for Linux, macOS, and Windows.

## Security Note

Use only on systems you own or are explicitly authorized to test.
