package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/root-Manas/macaron/internal/app"
	"github.com/root-Manas/macaron/internal/cfg"
	"github.com/root-Manas/macaron/internal/cliui"
	"github.com/root-Manas/macaron/internal/model"
	"github.com/spf13/pflag"
)

const version = "3.1.0"

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		cliui.PrintBanner(os.Stderr, version, false)
		printHelp()
		return 0
	}

	cmd := strings.ToLower(strings.TrimSpace(os.Args[1]))

	switch cmd {
	case "scan":
		return runScan(os.Args[2:])
	case "status":
		return runStatus(os.Args[2:])
	case "results":
		return runResults(os.Args[2:])
	case "setup":
		return runSetup(os.Args[2:])
	case "export":
		return runExport(os.Args[2:])
	case "config":
		return runConfig(os.Args[2:])
	case "api":
		return runAPI(os.Args[2:])
	case "uninstall":
		return runUninstall(os.Args[2:])
	case "guide":
		printGuide()
		return 0
	case "version", "--version", "-version", "-v":
		fmt.Printf("macaron %s\n", version)
		return 0
	case "help", "--help", "-help", "-h":
		cliui.PrintBanner(os.Stderr, version, false)
		printHelp()
		return 0
	default:
		// Legacy compat: treat unknown first arg as a scan target if it looks like a domain.
		if looksLikeDomain(cmd) {
			return runScan(os.Args[1:])
		}
		cliui.Err("unknown command: %s  (run 'macaron help')", cmd)
		return 1
	}
}

// ─── scan ────────────────────────────────────────────────────────────────────

func runScan(args []string) int {
	fs := pflag.NewFlagSet("scan", pflag.ContinueOnError)
	var (
		targets []string
		file    string
		stdin   bool
		mode    string
		rate    int
		threads int
		stages  string
		profile string
		quiet   bool
		storage string
	)
	fs.StringArrayVarP(&targets, "target", "t", nil, "Target domain(s) (repeatable)")
	fs.StringVarP(&file, "file", "f", "", "Read targets from file (one per line)")
	fs.BoolVar(&stdin, "stdin", false, "Read targets from stdin")
	fs.StringVarP(&mode, "mode", "m", "wide", "Scan mode: wide|narrow|fast|deep|osint")
	fs.IntVar(&rate, "rate", 150, "Request rate hint")
	fs.IntVar(&threads, "threads", 30, "Concurrent workers")
	fs.StringVar(&stages, "stages", "all", "Comma-separated stages: subdomains,http,ports,urls,vulns")
	fs.StringVarP(&profile, "profile", "p", "balanced", "Workflow profile: passive|balanced|aggressive")
	fs.BoolVarP(&quiet, "quiet", "q", false, "Suppress progress output")
	fs.StringVar(&storage, "storage", "", "Storage root (default: ./storage)")
	_ = fs.Parse(args)

	// Positional args are also targets.
	for _, a := range fs.Args() {
		targets = append(targets, a)
	}

	if !quiet {
		cliui.PrintBanner(os.Stderr, version, false)
	}

	home, err := macaronHome(storage)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	application, err := app.New(home)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	config, err := cfg.Load(home)
	if err != nil {
		cliui.Err("loading config: %v", err)
		return 1
	}

	allTargets, err := app.ParseTargets(targets, file, stdin)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		cliui.Err("%v", err)
		return 1
	}
	if len(allTargets) == 0 {
		cliui.Err("no targets provided — use -t <domain> or pass positional args")
		return 1
	}

	applyProfile(profile, &mode, &rate, &threads, &stages)
	if rate <= 0 {
		cliui.Err("--rate must be > 0")
		return 1
	}
	if threads <= 0 {
		cliui.Err("--threads must be > 0")
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	start := time.Now()
	modeVal := model.Mode(strings.ToLower(mode))
	var renderer *cliui.LiveRenderer
	if !quiet {
		renderer = cliui.NewLiveRenderer(os.Stdout)
		defer renderer.Close()
		cliui.Info("profile=%s mode=%s stages=%s rate=%d threads=%d targets=%d",
			profile, mode, stages, rate, threads, len(allTargets))
	}
	res, err := application.Scan(ctx, app.ScanArgs{
		Targets:       allTargets,
		Mode:          modeVal,
		Rate:          rate,
		Threads:       threads,
		Quiet:         quiet,
		EnabledStages: app.ParseStages(stages),
		APIKeys:       config.APIKeys,
		Progress: func(ev model.StageEvent) {
			if renderer != nil {
				renderer.Handle(ev)
			}
		},
	})
	if err != nil {
		cliui.Err("scan failed: %v", err)
		return 1
	}
	if !quiet {
		fmt.Println(app.RenderScanSummary(res))
		cliui.OK("finished %d target(s) in %s", len(res), time.Since(start).Round(time.Millisecond))
	}
	return 0
}

// ─── status ──────────────────────────────────────────────────────────────────

func runStatus(args []string) int {
	fs := pflag.NewFlagSet("status", pflag.ContinueOnError)
	var limit int
	var storage string
	fs.IntVarP(&limit, "limit", "n", 50, "Number of recent scans to show")
	fs.StringVar(&storage, "storage", "", "Storage root")
	_ = fs.Parse(args)

	home, err := macaronHome(storage)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	application, err := app.New(home)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	out, err := application.ShowStatus(limit)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	fmt.Print(out)
	return 0
}

// ─── results ─────────────────────────────────────────────────────────────────

func runResults(args []string) int {
	fs := pflag.NewFlagSet("results", pflag.ContinueOnError)
	var (
		domain  string
		id      string
		what    string
		limit   int
		storage string
	)
	fs.StringVarP(&domain, "domain", "d", "", "Filter by target domain")
	fs.StringVar(&id, "id", "", "Fetch specific scan by ID")
	fs.StringVarP(&what, "what", "w", "all", "View: all|subdomains|live|ports|urls|js|vulns")
	fs.IntVarP(&limit, "limit", "n", 50, "Output limit per category")
	fs.StringVar(&storage, "storage", "", "Storage root")
	_ = fs.Parse(args)

	home, err := macaronHome(storage)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	application, err := app.New(home)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	out, err := application.ShowResults(domain, id, what, limit)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	fmt.Print(out)
	return 0
}

// ─── setup ───────────────────────────────────────────────────────────────────

func runSetup(args []string) int {
	fs := pflag.NewFlagSet("setup", pflag.ContinueOnError)
	var install bool
	fs.BoolVarP(&install, "install", "i", false, "Auto-install missing tools that support it")
	_ = fs.Parse(args)

	tools := app.SetupCatalog()
	fmt.Print(app.RenderSetup(tools))

	if install {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		installed, err := app.InstallMissingTools(ctx, tools)
		if err != nil {
			cliui.Err("install error: %v", err)
			return 1
		}
		if len(installed) == 0 {
			cliui.Info("no installable tools were missing")
		} else {
			cliui.OK("installed: %s", strings.Join(installed, ", "))
		}
		fmt.Print(app.RenderSetup(app.SetupCatalog()))
	}
	return 0
}

// ─── export ──────────────────────────────────────────────────────────────────

func runExport(args []string) int {
	fs := pflag.NewFlagSet("export", pflag.ContinueOnError)
	var output, domain, storage string
	fs.StringVarP(&output, "output", "o", "", "Output file path")
	fs.StringVarP(&domain, "domain", "d", "", "Filter by domain")
	fs.StringVar(&storage, "storage", "", "Storage root")
	_ = fs.Parse(args)

	home, err := macaronHome(storage)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	application, err := app.New(home)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	path, err := application.Export(output, domain)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	cliui.OK("exported → %s", path)
	return 0
}

// ─── config ──────────────────────────────────────────────────────────────────

func runConfig(args []string) int {
	fs := pflag.NewFlagSet("config", pflag.ContinueOnError)
	var storage string
	fs.StringVar(&storage, "storage", "", "Storage root")
	_ = fs.Parse(args)

	home, err := macaronHome(storage)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	application, err := app.New(home)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	fmt.Print(application.ShowConfig())
	return 0
}

// ─── api ─────────────────────────────────────────────────────────────────────

func runAPI(args []string) int {
	if len(args) == 0 {
		printAPIHelp()
		return 0
	}
	sub := strings.ToLower(strings.TrimSpace(args[0]))
	rest := args[1:]
	switch sub {
	case "list":
		return apiList(rest)
	case "set":
		return apiSet(rest)
	case "unset":
		return apiUnset(rest)
	case "import":
		return apiImport(rest)
	case "bulk":
		return apiBulk(rest)
	default:
		cliui.Err("unknown api subcommand: %s  (list|set|unset|import|bulk)", sub)
		return 1
	}
}

func apiList(args []string) int {
	fs := pflag.NewFlagSet("api list", pflag.ContinueOnError)
	var storage string
	fs.StringVar(&storage, "storage", "", "Storage root")
	_ = fs.Parse(args)

	home, err := macaronHome(storage)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	config, err := cfg.Load(home)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	items := cfg.MaskedKeys(config)
	if len(items) == 0 {
		cliui.Info("no API keys configured — use 'macaron api set key=value'")
		return 0
	}
	fmt.Printf("configured API keys (%s):\n", filepath.Join(home, "config.yaml"))
	for _, item := range items {
		fmt.Printf("  %s\n", item)
	}
	return 0
}

func apiSet(args []string) int {
	fs := pflag.NewFlagSet("api set", pflag.ContinueOnError)
	var storage string
	fs.StringVar(&storage, "storage", "", "Storage root")
	_ = fs.Parse(args)

	kvs := fs.Args()
	if len(kvs) == 0 {
		cliui.Err("usage: macaron api set key=value [key=value ...]")
		return 1
	}
	home, err := macaronHome(storage)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	config, err := cfg.Load(home)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	cfg.ApplySetAPI(config, kvs)
	if err := cfg.Save(home, config); err != nil {
		cliui.Err("%v", err)
		return 1
	}
	cliui.OK("saved %d key(s) → %s", len(kvs), filepath.Join(home, "config.yaml"))
	return 0
}

func apiUnset(args []string) int {
	// Reuse set with empty value to delete.
	if len(args) == 0 {
		cliui.Err("usage: macaron api unset key [key ...]")
		return 1
	}
	// Append "=" to each key so ApplySetAPI treats it as a deletion.
	kvs := make([]string, len(args))
	for i, k := range args {
		kvs[i] = strings.TrimSuffix(k, "=") + "="
	}
	return apiSet(kvs)
}

func apiImport(args []string) int {
	fs := pflag.NewFlagSet("api import", pflag.ContinueOnError)
	var storage string
	fs.StringVar(&storage, "storage", "", "Storage root")
	_ = fs.Parse(args)

	home, err := macaronHome(storage)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	config, err := cfg.Load(home)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	imported := cfg.ImportFromTools(config)
	if len(imported) == 0 {
		cliui.Info("no new keys found in installed tool configs")
		return 0
	}
	if err := cfg.Save(home, config); err != nil {
		cliui.Err("%v", err)
		return 1
	}
	for _, line := range imported {
		cliui.OK("imported: %s", line)
	}
	return 0
}

func apiBulk(args []string) int {
	fs := pflag.NewFlagSet("api bulk", pflag.ContinueOnError)
	var file, storage string
	fs.StringVarP(&file, "file", "f", "", "YAML file with api_keys map (required)")
	fs.StringVar(&storage, "storage", "", "Storage root")
	_ = fs.Parse(args)

	if file == "" && len(fs.Args()) > 0 {
		file = fs.Args()[0]
	}
	if file == "" {
		cliui.Err("usage: macaron api bulk --file keys.yaml")
		return 1
	}
	home, err := macaronHome(storage)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	config, err := cfg.Load(home)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	count, err := cfg.BulkLoadFile(config, file)
	if err != nil {
		cliui.Err("%v", err)
		return 1
	}
	if err := cfg.Save(home, config); err != nil {
		cliui.Err("%v", err)
		return 1
	}
	cliui.OK("loaded %d key(s) from %s", count, file)
	return 0
}

// ─── uninstall ───────────────────────────────────────────────────────────────

func runUninstall(args []string) int {
	fs := pflag.NewFlagSet("uninstall", pflag.ContinueOnError)
	var storage string
	var yes bool
	fs.StringVar(&storage, "storage", "", "Storage root to also remove (optional)")
	fs.BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	_ = fs.Parse(args)

	execPath, err := os.Executable()
	if err != nil {
		cliui.Err("cannot locate binary: %v", err)
		return 1
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		cliui.Err("cannot resolve symlink: %v", err)
		return 1
	}

	fmt.Printf("binary path  : %s\n", execPath)

	home, _ := macaronHome(storage)
	removeStorage := false

	if !yes {
		fmt.Printf("remove binary %s? [y/N] ", execPath)
		if !readYes() {
			fmt.Println("aborted")
			return 0
		}
		if home != "" {
			fmt.Printf("remove storage directory %s? [y/N] ", home)
			removeStorage = readYes()
		}
	} else {
		removeStorage = storage != ""
	}

	if err := os.Remove(execPath); err != nil {
		cliui.Err("failed to remove binary: %v", err)
		return 1
	}
	cliui.OK("removed binary: %s", execPath)

	if removeStorage && home != "" {
		if err := os.RemoveAll(home); err != nil {
			cliui.Warn("could not remove storage: %v", err)
		} else {
			cliui.OK("removed storage: %s", home)
		}
	}

	fmt.Println("macaron uninstalled")
	return 0
}

func readYes() bool {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.ToLower(strings.TrimSpace(scanner.Text())) == "y"
}

// ─── help ────────────────────────────────────────────────────────────────────

func printHelp() {
	fmt.Print(`usage:
  macaron <command> [flags]

commands:
  scan       run a recon pipeline against one or more targets
  status     show scan history
  results    inspect scan output
  setup      check / install required tools
  export     dump results to JSON
  config     show storage and config paths
  api        manage global API keys
  uninstall  remove macaron from this system
  guide      first-principles workflow walkthrough
  version    print version

scan flags:
  -t, --target DOMAIN    target domain (repeatable)
  -f, --file FILE        read targets from file
      --stdin            read targets from stdin
  -m, --mode MODE        wide|narrow|fast|deep|osint  (default: wide)
  -p, --profile NAME     passive|balanced|aggressive  (default: balanced)
      --stages LIST      subdomains,http,ports,urls,vulns  (default: all)
      --rate N           request rate hint  (default: 150)
      --threads N        workers  (default: 30)
  -q, --quiet            suppress progress output
      --storage DIR      custom storage root

api subcommands:
  macaron api list
  macaron api set key=value [key=value ...]
  macaron api unset key [key ...]
  macaron api import            # pull keys from installed tool configs
  macaron api bulk -f keys.yaml # load many keys from a YAML file

examples:
  macaron scan -t example.com
  macaron scan -t example.com -p aggressive --stages subdomains,http,vulns
  macaron scan -f targets.txt -p passive -q
  macaron status
  macaron results -d example.com -w vulns
  macaron api set securitytrails=YOURKEY shodan=YOURKEY
  macaron api import
  macaron setup --install
  macaron uninstall
`)
}

func printAPIHelp() {
	fmt.Print(`macaron api — global API key management

subcommands:
  list                  show configured keys (masked)
  set key=value ...     set one or more keys
  unset key ...         remove key(s)
  import                import from installed tool configs (subfinder, amass…)
  bulk -f keys.yaml     load many keys at once from a YAML file

the bulk file format:
  api_keys:
    securitytrails: YOUR_KEY
    shodan: YOUR_KEY
    virustotal: YOUR_KEY

keys set here are automatically injected into supported tools (e.g. subfinder)
when macaron runs them, without touching your tool-specific configs.
`)
}

func printGuide() {
	fmt.Print(`macaron — first-principles workflow

1. provision once:
   macaron setup --install
   macaron api set securitytrails=KEY shodan=KEY virustotal=KEY
   # or pull keys already in your tools:
   macaron api import

2. enumerate with intent:
   macaron scan -t target.com -p passive        # low-noise, passive only
   macaron scan -t target.com -p balanced       # default practical pipeline
   macaron scan -t target.com -p aggressive \
     --stages subdomains,http,ports,urls,vulns  # full depth

3. triage:
   macaron status
   macaron results -d target.com -w live
   macaron results -d target.com -w vulns

4. share:
   macaron export -o target.json

profiles:
  passive     osint-only, low rate, no active probing
  balanced    default — enumeration + probing + vuln scan
  aggressive  max concurrency, all stages, authorized testing only

authorized use only.
`)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func applyProfile(profile string, mode *string, rate *int, threads *int, stages *string) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "passive":
		if *mode == "wide" {
			*mode = "osint"
		}
		if *rate == 150 {
			*rate = 40
		}
		if *threads == 30 {
			*threads = 10
		}
		if *stages == "all" {
			*stages = "subdomains,http,urls"
		}
	case "aggressive":
		if *rate == 150 {
			*rate = 350
		}
		if *threads == 30 {
			*threads = 70
		}
	}
}

func macaronHome(override string) (string, error) {
	if strings.TrimSpace(override) != "" {
		return filepath.Clean(override), nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(cwd, "storage"), nil
}

func looksLikeDomain(s string) bool {
	if strings.HasPrefix(s, "-") || strings.Contains(s, " ") {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	tld := parts[len(parts)-1]
	// TLD must be alphabetic-only and at least 2 characters.
	if len(tld) < 2 {
		return false
	}
	for _, c := range tld {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}
