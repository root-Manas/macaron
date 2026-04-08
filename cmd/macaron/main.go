package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/root-Manas/macaron/internal/app"
	"github.com/root-Manas/macaron/internal/cfg"
	"github.com/root-Manas/macaron/internal/cliui"
	"github.com/root-Manas/macaron/internal/model"
	"github.com/root-Manas/macaron/internal/ui"
	"github.com/spf13/pflag"
)

const version = "3.0.0"

func main() {
	os.Exit(run())
}

func run() int {
	normalizeLegacyArgs()
	normalizeCommandArgs()
	normalizeCompactFlags()

	var (
		scanTargets  []string
		status       bool
		results      bool
		listTools    bool
		export       bool
		configCmd    bool
		pipeline     bool
		serve        bool
		filePath     string
		useStdin     bool
		domain       string
		scanID       string
		what         string
		mode         string
		fast         bool
		narrow       bool
		rate         int
		threads      int
		limit        int
		output       string
		quiet        bool
		showVersion  bool
		serveAddr    string
		storagePath  string
		stages       string
		setAPI       []string
		showAPI      bool
		setup        bool
		installTools bool
		profile      string
		guide        bool
	)

	pflag.StringArrayVar(&scanTargets, "scn", nil, "Scan target(s)")
	pflag.BoolVar(&status, "sts", false, "Show scan status")
	pflag.BoolVar(&results, "res", false, "Show results")
	pflag.BoolVar(&listTools, "lst", false, "List external tool availability")
	pflag.BoolVar(&export, "exp", false, "Export results to JSON")
	pflag.BoolVar(&configCmd, "cfg", false, "Show config paths")
	pflag.BoolVar(&pipeline, "pip", false, "Show pipeline path (v2 native pipeline is built-in)")
	pflag.BoolVar(&serve, "srv", false, "Start web dashboard server")

	pflag.StringVar(&filePath, "fil", "", "Read targets from file")
	pflag.BoolVar(&useStdin, "inp", false, "Read targets from stdin")
	pflag.StringVar(&domain, "dom", "", "Filter by domain")
	pflag.StringVar(&scanID, "sid", "", "Fetch specific scan ID")
	pflag.StringVar(&what, "wht", "all", "Result view: all|subdomains|live|ports|urls|js|vulns")
	pflag.StringVar(&mode, "mod", "wide", "Mode: wide|narrow|fast|deep|osint")
	pflag.BoolVar(&fast, "fst", false, "Shortcut for mode fast")
	pflag.BoolVar(&narrow, "nrw", false, "Shortcut for mode narrow")
	pflag.IntVar(&rate, "rte", 150, "Request rate hint")
	pflag.IntVar(&threads, "thr", 30, "Worker threads")
	pflag.IntVar(&limit, "lim", 50, "Output limit")
	pflag.StringVar(&output, "out", "", "Output file")
	pflag.BoolVar(&quiet, "qut", false, "Quiet output")
	pflag.BoolVar(&showVersion, "ver", false, "Show version")
	pflag.StringVar(&serveAddr, "adr", "127.0.0.1:8088", "Dashboard bind address")
	pflag.StringVar(&storagePath, "str", "", "Storage root directory (default: ./storage)")
	pflag.StringVar(&stages, "stg", "all", "Comma-separated stages: subdomains,http,ports,urls,vulns")
	pflag.StringArrayVar(&setAPI, "sak", nil, "Set API key as name=value (repeatable). Use empty value to unset.")
	pflag.BoolVar(&showAPI, "shk", false, "Show configured API keys (masked)")
	pflag.BoolVar(&setup, "stp", false, "Show setup screen with tool installation status")
	pflag.BoolVar(&installTools, "ins", false, "Install missing supported tools (Linux)")
	pflag.StringVar(&profile, "prf", "balanced", "Workflow profile: passive|balanced|aggressive")
	pflag.BoolVar(&guide, "gud", false, "Show first-principles workflow guide")
	pflag.Parse()

	if showVersion {
		fmt.Printf("macaronV2 %s (Go %s, stable)\n", version, runtime.Version())
		return 0
	}
	if guide {
		printGuide()
		return 0
	}

	home, err := macaronHome(storagePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	application, err := app.New(home)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	config, err := cfg.Load(home)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		return 1
	}
	if len(setAPI) > 0 {
		cfg.ApplySetAPI(config, setAPI)
		if err := cfg.Save(home, config); err != nil {
			fmt.Fprintf(os.Stderr, "error saving config: %v\n", err)
			return 1
		}
		fmt.Printf("Saved API keys to %s\n", filepath.Join(home, "config.yaml"))
		return 0
	}
	if showAPI {
		items := cfg.MaskedKeys(config)
		if len(items) == 0 {
			fmt.Println("No API keys configured")
			return 0
		}
		fmt.Println("Configured API keys:")
		for _, item := range items {
			fmt.Printf("  - %s\n", item)
		}
		return 0
	}
	if setup || installTools {
		tools := app.SetupCatalog()
		fmt.Print(app.RenderSetup(tools))
		if installTools {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			installed, err := app.InstallMissingTools(ctx, tools)
			if err != nil {
				fmt.Fprintf(os.Stderr, "setup error: %v\n", err)
				return 1
			}
			if len(installed) == 0 {
				fmt.Println("No installable missing tools found.")
			} else {
				fmt.Printf("Installed: %s\n", strings.Join(installed, ", "))
			}
			fmt.Print(app.RenderSetup(app.SetupCatalog()))
		}
		return 0
	}

	if configCmd {
		fmt.Print(application.ShowConfig())
		return 0
	}
	if pipeline {
		fmt.Printf("Pipeline (macaronV2 native): %s\n", filepath.Join(home, "pipeline.v2.yaml"))
		return 0
	}
	if listTools {
		for _, t := range app.ListTools() {
			state := "missing"
			if t.Installed {
				state = "installed"
			}
			fmt.Printf("%-12s %s\n", t.Name, state)
		}
		return 0
	}
	if status {
		out, err := application.ShowStatus(limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Print(out)
		return 0
	}
	if results {
		out, err := application.ShowResults(domain, scanID, what, limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Print(out)
		return 0
	}
	if export {
		path, err := application.Export(output, domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Printf("Exported: %s\n", path)
		return 0
	}
	if serve {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		server := ui.New(application.Store)
		if err := server.Serve(ctx, serveAddr); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return 0
	}

	targets, err := app.ParseTargets(scanTargets, filePath, useStdin)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if len(targets) == 0 {
		printHelp()
		return 0
	}
	applyProfile(profile, &mode, &rate, &threads, &stages)
	if fast {
		mode = "fast"
	}
	if narrow {
		mode = "narrow"
	}
	if rate <= 0 {
		fmt.Fprintln(os.Stderr, "error: --rate must be > 0")
		return 1
	}
	if threads <= 0 {
		fmt.Fprintln(os.Stderr, "error: --threads must be > 0")
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
	}
	if !quiet {
		fmt.Printf("Workflow profile: %s | mode=%s | stages=%s | rate=%d | threads=%d\n", profile, mode, stages, rate, threads)
	}
	res, err := application.Scan(ctx, app.ScanArgs{
		Targets:       targets,
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
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		return 1
	}
	if !quiet {
		fmt.Println("macaronV2 scan summary")
		fmt.Println(app.RenderScanSummary(res))
		fmt.Printf("Completed %d target(s) in %s\n", len(res), time.Since(start).Round(time.Millisecond))
	}
	return 0
}

func printHelp() {
	fmt.Println(`macaron - reconnaissance workflow tool

Usage:
  macaron scan example.com
  macaron scan example.com --profile passive
  macaron scan example.com --stages subdomains,http,urls
  macaron status
  macaron results --dom example.com --wht live
  macaron serve --addr 127.0.0.1:8088
  macaron setup
  macaron export --out results.json

Core commands:
  scan TARGET            Scan one or more targets (positional or --scn)
  status                 Show recent scan summaries
  results                Show detailed scan results
  serve                  Start web dashboard
  setup                  Show tool installation status
  export                 Export scan results to JSON
  guide                  Show workflow guide

Scan flags:
  --scn TARGET           Scan one or more targets (repeatable)
  --fil FILE             Read targets from file
  --inp                  Read targets from stdin
  --profile NAME         passive|balanced|aggressive (default: balanced)
  --stages LIST          subdomains,http,ports,urls,vulns (default: all)
  --mod MODE             wide|narrow|fast|deep|osint
  --rate N               Request rate hint (default: 150)
  --threads N            Worker threads (default: 30)

Output flags:
  --dom DOMAIN           Filter results by domain
  --wht VIEW             all|subdomains|live|ports|urls|js|vulns
  --lim N                Output row limit (default: 50)
  --out FILE             Output file path
  --quiet                Suppress progress output

API keys:
  --set-api k=v          Save API key (e.g. securitytrails=KEY)
  --show-api             Show configured API keys (masked)

Other:
  --storage DIR          Storage root (default: ./storage)
  --addr ADDR            Dashboard bind address (default: 127.0.0.1:8088)
  --version              Show version
  --guide                Show first-principles workflow guide`)
}

func normalizeLegacyArgs() {
	for i, arg := range os.Args {
		if arg == "-setup" {
			os.Args[i] = "-stp"
		}
		if arg == "-install-tools" {
			os.Args[i] = "-ins"
		}
	}
}

func normalizeCommandArgs() {
	if len(os.Args) < 2 {
		return
	}
	cmd := strings.ToLower(strings.TrimSpace(os.Args[1]))
	rest := os.Args[2:]
	switch cmd {
	case "scan":
		args := []string{os.Args[0]}
		for _, tok := range rest {
			if strings.HasPrefix(tok, "-") {
				args = append(args, tok)
				continue
			}
			args = append(args, "--scn", tok)
		}
		os.Args = args
	case "status":
		os.Args = append([]string{os.Args[0], "--sts"}, rest...)
	case "results":
		os.Args = append([]string{os.Args[0], "--res"}, rest...)
	case "serve":
		os.Args = append([]string{os.Args[0], "--srv"}, rest...)
	case "setup":
		os.Args = append([]string{os.Args[0], "--stp"}, rest...)
	case "export":
		os.Args = append([]string{os.Args[0], "--exp"}, rest...)
	case "config":
		os.Args = append([]string{os.Args[0], "--cfg"}, rest...)
	case "guide":
		os.Args = append([]string{os.Args[0], "--gud"}, rest...)
	}
}

func normalizeCompactFlags() {
	flagMap := map[string]string{
		"scan": "scn", "s": "scn", "scn": "scn",
		"status": "sts", "S": "sts", "sts": "sts",
		"results": "res", "R": "res", "res": "res",
		"list-tools": "lst", "L": "lst", "lst": "lst",
		"export": "exp", "E": "exp", "exp": "exp",
		"config": "cfg", "C": "cfg", "cfg": "cfg",
		"pipeline": "pip", "P": "pip", "pip": "pip",
		"serve": "srv", "srv": "srv",
		"file": "fil", "F": "fil", "fil": "fil",
		"stdin": "inp", "inp": "inp",
		"domain": "dom", "d": "dom", "dom": "dom",
		"id": "sid", "sid": "sid",
		"what": "wht", "w": "wht", "wht": "wht",
		"mode": "mod", "m": "mod", "mod": "mod",
		"fast": "fst", "f": "fst", "fst": "fst",
		"narrow": "nrw", "n": "nrw", "nrw": "nrw",
		"rate": "rte", "rte": "rte",
		"threads": "thr", "thr": "thr",
		"limit": "lim", "lim": "lim",
		"output": "out", "o": "out", "out": "out",
		"quiet": "qut", "q": "qut", "qut": "qut",
		"version": "ver", "ver": "ver",
		"addr": "adr", "adr": "adr",
		"storage": "str", "str": "str",
		"stages": "stg", "stg": "stg",
		"set-api": "sak", "sak": "sak",
		"show-api": "shk", "shk": "shk",
		"setup": "stp", "stp": "stp",
		"install-tools": "ins", "ins": "ins",
		"profile": "prf", "prf": "prf",
		"guide": "gud", "gud": "gud",
	}
	args := make([]string, 0, len(os.Args))
	args = append(args, os.Args[0])
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && len(arg) > 2 {
			key := strings.TrimPrefix(arg, "-")
			val := ""
			if i := strings.IndexRune(key, '='); i >= 0 {
				val = key[i:]
				key = key[:i]
			}
			if mapped, ok := flagMap[key]; ok {
				args = append(args, "--"+mapped+val)
				continue
			}
		}
		if strings.HasPrefix(arg, "--") {
			key := strings.TrimPrefix(arg, "--")
			val := ""
			if i := strings.IndexRune(key, '='); i >= 0 {
				val = key[i:]
				key = key[:i]
			}
			if mapped, ok := flagMap[key]; ok {
				args = append(args, "--"+mapped+val)
				continue
			}
		}
		args = append(args, arg)
	}
	os.Args = args
}

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
	default:
		// balanced defaults are already encoded in flags.
	}
}

func printGuide() {
	fmt.Println(`macaron workflow guide

1) Setup once:
   macaron setup
   macaron --ins
   macaron --set-api securitytrails=YOUR_KEY

2) Run scans:
   macaron scan target.com --profile passive
   macaron scan target.com --profile balanced
   macaron scan target.com --profile aggressive --stages subdomains,http,ports,urls,vulns

3) Inspect and triage:
   macaron status
   macaron results --dom target.com --wht live
   macaron serve

4) Export:
   macaron export --out target.json

Profiles:
  passive      low rate, low concurrency, passive collection only
  balanced     default practical pipeline
  aggressive   high concurrency for authorized deep testing only`)
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
