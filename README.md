# macaronV2

High-performance reconnaissance pipeline rewritten in **Go (stable language runtime)**.

`macaronV2` replaces the previous Python monolith with a concurrent Go architecture focused on speed, simpler operations, and clean result visibility in terminal and browser.

## Why v2

- Full rewrite in Go (`go 1.22` stable)
- Native concurrent collectors and HTTP probing
- JSON scan snapshots with fast status/result lookup
- Built-in dashboard server (`--serve`) with clear HTML/CSS UI
- Optional integration with external recon tools when installed

## Build

```bash
go mod tidy
go build -o macaron ./cmd/macaron
```

## Quick Start

```bash
# Scan one target
./macaron -s example.com

# Fast mode
./macaron -s example.com -f

# Multiple targets from file
./macaron -F targets.txt

# Show status and results
./macaron -S
./macaron -R -d example.com -w live

# Export JSON
./macaron -E -o results.json

# Launch dashboard
./macaron --serve --addr 127.0.0.1:8088
# open http://127.0.0.1:8088
```

## Commands

```text
macaron [OPTIONS]

SCANNING:
  -s, --scan TARGET        Scan target(s)
  -F, --file FILE          Scan targets from file
  --stdin                  Read targets from stdin
  -m, --mode MODE          wide|narrow|fast|deep|osint
  -f, --fast               Shortcut for -m fast
  -n, --narrow             Shortcut for -m narrow
  --rate N                 Request rate hint
  --threads N              Worker threads
  -q, --quiet              Suppress summary output

RESULTS:
  -S, --status             Show scan status summaries
  -R, --results            Show scan results
  -d, --domain DOMAIN      Filter results by domain
  --id SCAN_ID             Show a specific scan
  -w, --what TYPE          all|subdomains|live|ports|urls|js|vulns
  --limit N                Limit output lines
  -E, --export             Export JSON
  -o, --output FILE        Export output path

WEB UI:
  --serve                  Start local dashboard server
  --addr HOST:PORT         Dashboard bind address

SYSTEM:
  -L, --list-tools         Show optional external tool availability
  -C, --config             Show local data paths
  -P, --pipeline           Show v2 pipeline path marker
  --version                Show version
```

## Data Layout

Scans are stored under:

```text
~/.macaronv2/
  scans/   # full JSON scan records
  latest/  # latest scan pointer per target
```

## Speed Notes

`macaronV2` is faster primarily because it:

- uses goroutine worker pools for HTTP probing and URL discovery
- minimizes process-spawn overhead by using native Go collectors
- reuses HTTP connections via pooled transport
- writes compact structured artifacts for quick post-scan reads

## Migration Note

This repository is now centered on the **stable Go rewrite**. Legacy Python packaging/test files were removed in favor of Go module build and tests.
