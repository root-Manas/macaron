# macaronV2

Fast reconnaissance workflow in Go with SQLite-backed persistence and an operator-focused dashboard.

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
macaron scan example.com --profile balanced
macaron status
macaron serve --addr 127.0.0.1:8088
```

## Core Commands

```bash
macaron setup
macaron scan <target...>
macaron status
macaron results -d <domain> -w <type>
macaron serve
macaron export -o results.json
```

## Profiles

- `passive`: low-noise collection
- `balanced`: default practical workflow
- `aggressive`: high-throughput authorized testing

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
macaron --install-tools
macaron --set-api securitytrails=YOUR_KEY
macaron --show-api
```

## Stage Control

```bash
macaron scan example.com --stages subdomains,http,urls
```

Available stages: `subdomains,http,ports,urls,vulns`

## Dashboard

```bash
macaron serve --addr 127.0.0.1:8088
```

Open `http://127.0.0.1:8088`.

## Release

```bash
git tag v3.0.1
git push origin v3.0.1
```

Tagged releases build and publish binaries for Linux, macOS, and Windows.

## Security Note

Use only on systems you own or are explicitly authorized to test.
