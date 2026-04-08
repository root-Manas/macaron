# macaron

Reconnaissance workflow tool written in Go. SQLite-backed persistence, a live CLI progress view, and a web dashboard for inspecting findings.

## Workflow

```
setup → scan → status/results → serve → export
```

1. **setup** – verify tool installation and configure API keys
2. **scan** – collect subdomains, probe live hosts, scan ports, discover URLs, run vuln checks
3. **status / results** – triage findings in the terminal
4. **serve** – open everything in the web dashboard
5. **export** – write a JSON report for sharing or archiving

## Quick Start

```bash
git clone https://github.com/root-Manas/macaron.git
cd macaron
chmod +x install.sh
./install.sh
source ~/.bashrc

macaron setup
macaron scan example.com --profile balanced
macaron status
macaron serve
```

## Commands

```
macaron setup                              Show tool installation status
macaron scan <target>                      Scan a target
macaron status                             List recent scans
macaron results --dom <domain>             Show results for a domain
macaron serve                              Start the web dashboard
macaron export --out results.json          Export all results to JSON
macaron guide                              Show workflow guide
```

## Scan Options

```
--profile passive|balanced|aggressive      Workflow preset (default: balanced)
--stages subdomains,http,ports,urls,vulns  Enable specific stages (default: all)
--mod wide|narrow|fast|deep|osint          Scan mode (default: wide)
--rate N                                   Request rate hint (default: 150)
--threads N                                Worker threads (default: 30)
--fil FILE                                 Read targets from a file
--inp                                      Read targets from stdin
```

## Profiles

| Profile    | Rate | Threads | Stages                  |
|------------|------|---------|-------------------------|
| passive    | 40   | 10      | subdomains, http, urls  |
| balanced   | 150  | 30      | all                     |
| aggressive | 350  | 70      | all                     |

## Storage

Default storage root: `./storage`

```
storage/
  macaron.db          SQLite database with all scan results
  config.yaml         API key configuration
  <target>/
    <scan-id>.json    Full scan result
    latest.txt        ID of the most recent scan for this target
```

## API Keys

```bash
macaron --set-api securitytrails=YOUR_KEY
macaron --show-api
```

## Stages

| Stage      | What it does                                |
|------------|---------------------------------------------|
| subdomains | crt.sh + subfinder/assetfinder/findomain    |
| http       | probe each host over HTTPS then HTTP        |
| ports      | TCP connect scan on common ports            |
| urls       | Wayback Machine URL discovery               |
| vulns      | nuclei template scan against live hosts     |

## Web Dashboard

```bash
macaron serve --addr 127.0.0.1:8088
```

Open `http://127.0.0.1:8088`.

The dashboard shows scan results, a live host table, subdomain lists, URLs, vulnerability findings, a geo heat map, and an **analytics** view with daily activity, top targets by vuln count, and severity distribution across all scans. Press `Ctrl-C` to stop.

## Install

```bash
git clone https://github.com/root-Manas/macaron.git
cd macaron
./install.sh        # builds and installs to ~/.local/bin/macaron
source ~/.bashrc
macaron --version
```

The installer requires Go 1.22 or later. To install optional external tools:

```bash
macaron setup          # show what is installed and what is missing
macaron --ins          # install missing Go-based tools (Linux)
```

## Release

Tag a version to trigger the CI build and binary release:

```bash
git tag v3.x.x
git push origin v3.x.x
```

Binaries are published for Linux, macOS, and Windows.

## Security

Use only on systems you own or are explicitly authorized to test.
