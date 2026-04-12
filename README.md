# macaron

Fast, researcher-oriented recon framework. Runs a chained enumeration pipeline — subdomains → live probing → port mapping → URL harvesting → vuln scanning — and stores everything in a local SQLite-backed store you can query and export.

---

## install

```bash
git clone https://github.com/root-Manas/macaron.git
cd macaron
chmod +x install.sh
./install.sh
source ~/.bashrc
```

Or grab a tagged binary from [Releases](https://github.com/root-Manas/macaron/releases).

---

## quick start

```bash
macaron setup --install          # check and install missing tools
macaron api set securitytrails=KEY shodan=KEY
macaron scan -t example.com
macaron status
macaron results -d example.com -w live
macaron export -o example.json
```

---

## commands

```
macaron scan       run recon pipeline
macaron status     list past scans
macaron results    query scan output
macaron setup      tool inventory + auto-install
macaron export     dump results to JSON
macaron config     show storage paths
macaron api        manage global API keys
macaron uninstall  remove macaron from this machine
macaron guide      workflow walkthrough
macaron version    print version
```

---

## scan

```bash
macaron scan -t target.com
macaron scan -t target.com -p passive
macaron scan -t target.com -p aggressive --stages subdomains,http,ports,urls,vulns
macaron scan -f targets.txt -p balanced -q
cat domains.txt | macaron scan --stdin
```

**flags**

| flag | default | description |
|------|---------|-------------|
| `-t, --target` | — | target domain (repeatable) |
| `-f, --file` | — | read targets from file |
| `--stdin` | — | read targets from stdin |
| `-m, --mode` | `wide` | `wide` \| `narrow` \| `fast` \| `deep` \| `osint` |
| `-p, --profile` | `balanced` | `passive` \| `balanced` \| `aggressive` |
| `--stages` | `all` | comma-separated: `subdomains,http,ports,urls,vulns` |
| `--rate` | `150` | request rate hint |
| `--threads` | `30` | concurrent workers |
| `-q, --quiet` | — | suppress progress output |
| `--storage` | `./storage` | custom storage root |

**profiles**

| profile | behaviour |
|---------|-----------|
| `passive` | OSINT-only, low rate, no active scanning |
| `balanced` | enumeration + probing + vuln scan |
| `aggressive` | max concurrency, all stages — authorized testing only |

---

## pipeline stages

| stage | what it does | tools used |
|-------|-------------|------------|
| `subdomains` | passive + active enumeration | crt.sh, subfinder, assetfinder, findomain, amass + SecurityTrails API |
| `http` | probe live hosts, grab titles | httpx fallback (native prober) |
| `ports` | TCP port sweep | naabu (if installed), native TCP dial fallback |
| `urls` | passive + active URL harvest | Wayback CDX, gau, katana |
| `vulns` | template-based vuln detection | nuclei |

Tools are used automatically when installed. Missing tools are skipped — pipeline keeps running.

---

## api management

macaron maintains a single global key store. All tools it runs pick up keys from here automatically — you don't configure them per-tool.

```bash
# set keys
macaron api set securitytrails=KEY shodan=KEY virustotal=KEY github=TOKEN

# remove a key
macaron api unset shodan

# view (masked)
macaron api list

# import from tools already on your system (subfinder, amass…)
macaron api import

# load many keys at once from a YAML file
macaron api bulk -f keys.yaml
```

**bulk file format**

```yaml
api_keys:
  securitytrails: YOUR_KEY
  shodan: YOUR_KEY
  virustotal: YOUR_KEY
  chaos: YOUR_KEY
  binaryedge: YOUR_KEY
  github: YOUR_TOKEN
```

Keys are written to `<storage>/config.yaml`. When subfinder runs, macaron injects the configured keys via a temporary provider config — your existing subfinder config is never modified.

---

## results

```bash
macaron status                          # recent scans
macaron results -d example.com          # full JSON
macaron results -d example.com -w live  # live hosts only
macaron results -d example.com -w vulns # findings only
macaron results --id <scan-id>          # specific scan
```

**-w values**: `all` · `subdomains` · `live` · `ports` · `urls` · `js` · `vulns`

---

## storage layout

```
storage/
  macaron.db          # indexed scan store
  config.yaml         # API keys + settings
  <target>/
    <scan-id>.json
    latest.txt
```

Override with `--storage /path/to/dir` or `MACARON_HOME` (env not yet supported — use the flag).

---

## setup

```bash
macaron setup           # show tool inventory
macaron setup --install # auto-install missing tools that support it
```

Supported tools (auto-installed with `--install`):

| tool | role |
|------|------|
| subfinder | subdomain enumeration |
| assetfinder | subdomain enumeration |
| amass | subdomain enumeration |
| httpx | HTTP probing |
| dnsx | DNS resolution |
| naabu | port scanning |
| gau | passive URL discovery |
| waybackurls | passive URL discovery |
| katana | active web crawling |
| gospider | active web crawling |
| hakrawler | active web crawling |
| ffuf | content fuzzing |
| gobuster | content fuzzing |
| nuclei | vulnerability scanning |

---

## uninstall

```bash
macaron uninstall
```

Locates and removes the macaron binary from PATH. Optionally removes the storage directory when prompted. Pass `--yes` to skip confirmation.

---

## security

Use macaron only on systems you own or have explicit written authorisation to test.

