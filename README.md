# macaron

Macaron is a CLI-only reconnaissance workflow for authorized security testing. It
collects subdomains, probes HTTP services, scans common TCP ports, discovers URLs,
and optionally runs Nuclei against live hosts. Scan history is stored locally in
SQLite with private JSON mirrors for convenient inspection.

Use Macaron only against systems you own or are explicitly authorized to assess.
HTTP probes, port checks, crawling, and vulnerability templates generate active
requests. The `passive` profile still performs HTTP and URL work; use
`--stages subdomains` when you need subdomain enumeration only.

## Install

Macaron requires Go 1.25 or newer. Choose one installation method.

### Option A: install globally with `go install`

This is the shortest route on Linux, macOS, WSL, and any system with Go:

```sh
go install github.com/root-Manas/macaron/cmd/macaron@latest
```

Go installs the binary into `GOBIN` when it is configured or, by default, into
`GOPATH/bin`. Make sure the actual install directory is on your `PATH`:

```sh
BIN_DIR="$(go env GOBIN)"
[ -n "$BIN_DIR" ] || BIN_DIR="$(go env GOPATH)/bin"
export PATH="$BIN_DIR:$PATH"
macaron version
```

To make it permanent for Bash or Zsh:

```sh
echo 'export PATH="$(go env GOPATH)/bin:$PATH"' >> ~/.profile
source ~/.profile
```

### Option B: clone and install with the project script

```sh
git clone https://github.com/root-Manas/macaron.git
cd macaron
./install.sh
source ~/.profile       # or open a new terminal
macaron version
```

`install.sh` builds `./cmd/macaron`, installs it to `~/.local/bin/macaron`, and
adds that directory to `.bashrc`, `.zshrc`, and `.profile` when needed.

### Option C: build manually

```sh
git clone https://github.com/root-Manas/macaron.git
cd macaron
go build -trimpath -o macaron ./cmd/macaron
./macaron version
```

To install that build globally on Unix-like systems:

```sh
install -Dm755 ./macaron "$HOME/.local/bin/macaron"
export PATH="$HOME/.local/bin:$PATH"
macaron version
```

On Windows PowerShell:

```powershell
git clone https://github.com/root-Manas/macaron.git
Set-Location macaron
go build -trimpath -o macaron.exe ./cmd/macaron
New-Item -ItemType Directory -Force "$HOME\bin" | Out-Null
Copy-Item .\macaron.exe "$HOME\bin\macaron.exe"
$env:Path = "$HOME\bin;$env:Path"
macaron version
```

For a permanent Windows PATH entry, add `$HOME\bin` through **System
Properties -> Environment Variables**, then open a new terminal.

### Verify the installation

```sh
command -v macaron
macaron version
macaron --help
```

On PowerShell, use `Get-Command macaron` instead of `command -v`.

External reconnaissance tools are optional. `macaron setup` reports their
availability, and `macaron setup --install` installs supported Go-based tools on
Linux. Tools must be available on `PATH` when a scan runs.

## End-to-end first run

The following walkthrough starts from an installed binary and produces a saved
scan, a human-readable result, machine-readable output, and an export file.
Use a domain you own or are authorized to assess.

```sh
# 1. Confirm the binary and inspect optional dependencies
macaron version
macaron setup

# 2. Optional: install supported missing tools on Linux
macaron setup --install

# 3. Inspect where local data will be stored
macaron config

# 4. Start with a controlled, lower-impact scan
macaron scan -t example.com -p passive -s subdomains,http,urls

# 5. Inspect the saved scan
macaron status
macaron results -d example.com
macaron results -d example.com -w live

# 6. Export results for another tool
macaron export -d example.com -o example.json
```

For automation:

```sh
macaron scan -t example.com -s subdomains,http -j > scan.json
macaron status -j | jq .
macaron results -d example.com -j | jq '.stats'
```

Every command supports `--help`. Human-readable output is the default; use
`--json` or `-j` where supported for shell pipelines and automation.

## Command reference

| Command | Purpose |
| --- | --- |
| `scan` | Run the reconnaissance pipeline for one or more targets |
| `status` | Show recent scan history |
| `results` | Inspect one scan or the latest scan for a target |
| `export` | Export saved scans as JSON |
| `setup` | Inspect or install optional external tools |
| `config` | Show active storage and configuration paths |
| `api` | Manage API keys used by optional providers |
| `uninstall` | Remove the installed binary and optionally its storage |
| `guide` | Print a first-principles workflow guide |
| `version` | Print the Macaron version |

Unknown positional arguments that look like domains are accepted as legacy
scan targets, so `macaron example.com` remains supported.

## Targets

Targets can be domains, IP addresses, or bare HTTP(S) origins:

```sh
macaron scan -t example.com -t example.org
macaron scan --file targets.txt
cat targets.txt | macaron scan --stdin
macaron scan example.com
```

Target files are one target per line. Blank lines and lines beginning with `#`
are ignored. Duplicate targets are removed and the final target list is sorted.
Paths, credentials, ports, query strings, and fragments in URL input are rejected;
`https://example.com` is accepted, while `https://example.com/path` is not.

## Scanning

```sh
# Conservative enumeration and web collection
macaron scan -t example.com -p passive

# Standard authorized assessment
macaron scan -t example.com -p balanced

# Higher throughput, all stages
macaron scan -t example.com -p aggressive

# Explicit stage selection
macaron scan -t example.com -s subdomains,http,urls

# Narrow mode probes only the original target
macaron scan -t example.com -m narrow

# Scan multiple targets concurrently
macaron scan -f targets.txt -W 4
```

### Scan flags

| Short | Long | Default | Purpose |
| --- | --- | --- | --- |
| `-t` | `--target` | - | Target; repeatable |
| `-f` | `--file` | - | Read targets from a file |
| `-i` | `--stdin` | off | Read targets from stdin |
| `-m` | `--mode` | `wide` | Probe all discovered hosts or only the target with `narrow` |
| `-p` | `--profile` | `balanced` | `passive`, `balanced`, or `aggressive` |
| `-s` | `--stages` | `all` | Comma-separated stage list |
| `-r` | `--rate` | `150` | Built-in probe dispatches per second; maximum 10,000 |
| `-T` | `--threads` | `30` | Workers per stage; maximum 500 |
| `-W` | `--target-workers` | `1` | Targets scanned concurrently; maximum 50 |
| `-q` | `--quiet` | off | Suppress interactive progress |
| `-j` | `--json` | off | Emit only machine-readable JSON |
| `-S` | `--storage` | platform default | Override the storage directory |

Long flags remain supported for readable scripts. `-j` automatically disables
the banner and live progress renderer so stdout contains valid JSON only.

### Stages

The available stages are:

| Stage | Behavior |
| --- | --- |
| `subdomains` | Certificate transparency, optional external tools, and configured providers |
| `http` | Probe discovered hosts and collect status, title, and technology metadata |
| `ports` | Scan common TCP ports, using Naabu when available and native checks otherwise |
| `urls` | Collect URLs from live/discovered hosts and derive JavaScript files |
| `vulns` | Run Nuclei against live hosts when Nuclei is installed |

`--stages all` enables every stage. Missing optional tools are skipped with a
warning. Installed tools that fail also produce scan warnings rather than silently
appearing successful.

`wide` probes all in-scope discovered hosts. `narrow` limits active HTTP and port
work to the original target. `--target-workers` controls parallel targets while
`--threads` controls workers inside each stage. Results retain input ordering.
If one target fails, active work is cancelled and completed results are returned
to the caller while the command exits non-zero.

## Inspecting results

```sh
macaron status
macaron status -n 20
macaron status -j

macaron results -d example.com
macaron results -d example.com -w live -n 100
macaron results -i SCAN_ID -w vulns
macaron results -d example.com -j

macaron export -d example.com -o example.json
macaron export -o all-scans.json
```

Result views are `all`, `subdomains`, `live`, `ports`, `urls`, `js`, and `vulns`.
`status -j`, `results -j`, and `scan -j` emit JSON only and are safe to pipe to
`jq` or another program. Export files are written atomically with private
permissions.

## Storage, durability, and recovery

The storage directory is selected in this order:

1. Explicit `--storage` / `-S` value
2. `MACARON_HOME` environment variable
3. Existing `./storage` directory for legacy compatibility
4. The operating system user config directory under `macaron`

Explicit paths are used exactly as supplied. Macaron stores:

```text
macaron.db       authoritative SQLite database
config.yaml      API key configuration
<target>/        private per-target JSON mirrors
```

SQLite is authoritative. Scan metadata and payloads are committed in a
transaction, WAL mode is enabled, and SQLite uses full synchronous durability.
Per-target JSON files and `latest.txt` are written through private temporary files
and atomic renames. On startup, missing mirrors are rebuilt from SQLite, so an
interrupted mirror write does not lose scan history.

Storage and configuration files are created with user-private permissions where
the operating system supports them. API keys are masked by `api list` and should
not be placed in shell history or committed to a repository.

## API keys

```sh
macaron api set securitytrails=KEY shodan=KEY
macaron api list
macaron api unset shodan
macaron api import
macaron api bulk -f keys.yaml
```

Bulk YAML accepts either form:

```yaml
api_keys:
  securitytrails: YOUR_KEY
  shodan: YOUR_KEY
```

or a flat key/value map. Macaron creates a temporary provider configuration for
Subfinder and removes it after the subprocess exits; it does not modify the
user's existing Subfinder configuration.

## Operational guidance

- Start with `-p passive` or an explicit `-s` list to control request scope.
- Use `-m narrow` when only the original target should receive active probes.
- Keep `-W` modest to avoid multiplying per-target stage concurrency.
- Use `-q` for quiet terminal runs and `-j` for automation.
- Review warnings in saved results; skipped optional tools are not findings.
- Use `macaron setup` before a production run to confirm tool availability.
- Use `macaron config` to verify the active storage location.

## Development

```sh
go build ./...
go test ./...
go vet ./...
```

The project is CLI-only. See [contributing](docs/contributing.md) for repository
conventions.
