# macaron

Macaron is a command-line reconnaissance workflow that collects subdomains, checks HTTP availability, scans common TCP ports, discovers URLs, and can run Nuclei against live hosts. It saves scan history locally in SQLite and JSON.

Use it only for systems you own or are authorized to assess. Port checks, HTTP probes, crawling, and Nuclei are active requests. The passive profile still probes HTTP hosts; use `--stages subdomains` for enumeration without those active stages.

## Install

Macaron requires Go 1.25 or newer to build. In Linux or WSL:

```sh
git clone https://github.com/root-Manas/macaron.git
cd macaron
go build -o macaron ./cmd/macaron
```

The `install.sh` script builds and installs to `~/.local/bin`. Macaron's external recon tools are optional; install the tools you need and make sure they are on `PATH`. `macaron setup` shows which tools are available. `macaron setup --install` installs missing Go-based tools on Linux only.

## Quick start

```sh
./macaron scan -t example.com
./macaron status
./macaron results -d example.com -w live
./macaron export -o example.json
```

Targets may be domain names, IP addresses, or bare origin URLs such as `https://example.com`. URL paths, credentials, query strings, and fragments are rejected. Target lists can come from flags, a file, or stdin:

```sh
./macaron scan -t example.com -t example.org
./macaron scan -t example.com -t example.org --target-workers 2
./macaron scan --file targets.txt
cat targets.txt | ./macaron scan --stdin
```

## Scans

```sh
./macaron scan -t example.com --profile passive
./macaron scan -t example.com --profile balanced
./macaron scan -t example.com --profile aggressive --stages subdomains,http,ports,urls,vulns
```

`balanced` is the default. `passive` lowers concurrency and skips port and vulnerability stages, but still runs HTTP probes and URL collection; choose stages explicitly when you need a passive-only run. `aggressive` increases rate and concurrency. The rate setting caps dispatch to the built-in HTTP and native port probes; external tools may use their own rate controls.

| Option | Default | Purpose |
| --- | --- | --- |
| `-t, --target` | — | Target; repeatable |
| `-f, --file` | — | Read one target per line |
| `--stdin` | — | Read targets from stdin |
| `-m, --mode` | `wide` | `wide` or `narrow` |
| `-p, --profile` | `balanced` | `passive`, `balanced`, or `aggressive` |
| `--stages` | `all` | Comma-separated `subdomains,http,ports,urls,vulns` |
| `--rate` | `150` | Built-in probe dispatches per second, capped at 10,000 |
| `--threads` | `30` | Concurrent workers, maximum 500 |
| `--target-workers` | `1` | Number of targets scanned concurrently, maximum 50 |
| `-q, --quiet` | off | Suppress progress display |
| `--storage` | user config directory | Override the data directory |

`--mode wide` probes all discovered hosts. `--mode narrow` limits active HTTP and port probes to the target itself. Use profiles to adjust concurrency and stage selection.

Macaron filters discovered names to the requested domain and its subdomains. HTTP probes stop at cross-host redirects to keep a probe from silently moving to another site. Missing optional tools are skipped. Failures from installed subdomain tools and Nuclei appear in scan warnings.

## API keys

Keys are stored in `config.yaml` under the Macaron data directory. On Unix-like systems the config and scan files are private to the current user. Subfinder receives a temporary provider config; Macaron does not edit Subfinder's own config.

```sh
./macaron api set securitytrails=KEY shodan=KEY
./macaron api list                 # values are masked
./macaron api unset shodan
./macaron api import               # import supported local tool configs
./macaron api bulk --file keys.yaml
```

The bulk YAML format is:

```yaml
api_keys:
  securitytrails: YOUR_KEY
  shodan: YOUR_KEY
```

Avoid putting live secrets in shell history or committing the bulk file.

## Results and storage

```sh
./macaron status
./macaron results -d example.com
./macaron results --id SCAN_ID -w vulns
./macaron results -d example.com -w subdomains
./macaron export --domain example.com --output example.json
```

Result views are `all`, `subdomains`, `live`, `ports`, `urls`, `js`, and `vulns`. Macaron stores `macaron.db`, `config.yaml`, and per-target JSON snapshots in the data directory. The default is the operating system's user config directory under `macaron`; set `MACARON_HOME` or pass `--storage` to choose another location. `--storage` takes precedence. An existing `./storage` directory is retained for compatibility when neither override is set.

## Development

```sh
go build ./...
go test ./...
go vet ./...
```

See [contributing](docs/contributing.md) for project conventions.
