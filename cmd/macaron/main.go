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

	pflag.StringArrayVarP(&scanTargets, "scan", "s", nil, "Scan target(s)")
	pflag.BoolVarP(&status, "status", "S", false, "Show scan status")
	pflag.BoolVarP(&results, "results", "R", false, "Show results")
	pflag.BoolVarP(&listTools, "list-tools", "L", false, "List external tool availability")
	pflag.BoolVarP(&export, "export", "E", false, "Export results to JSON")
	pflag.BoolVarP(&configCmd, "config", "C", false, "Show config paths")
	pflag.BoolVarP(&pipeline, "pipeline", "P", false, "Show pipeline path (v2 native pipeline is built-in)")
	pflag.BoolVar(&serve, "serve", false, "Start web dashboard server")

	pflag.StringVarP(&filePath, "file", "F", "", "Read targets from file")
	pflag.BoolVar(&useStdin, "stdin", false, "Read targets from stdin")
	pflag.StringVarP(&domain, "domain", "d", "", "Filter by domain")
	pflag.StringVar(&scanID, "id", "", "Fetch specific scan ID")
	pflag.StringVarP(&what, "what", "w", "all", "Result view: all|subdomains|live|ports|urls|js|vulns")
	pflag.StringVarP(&mode, "mode", "m", "wide", "Mode: wide|narrow|fast|deep|osint")
	pflag.BoolVarP(&fast, "fast", "f", false, "Shortcut for mode fast")
	pflag.BoolVarP(&narrow, "narrow", "n", false, "Shortcut for mode narrow")
	pflag.IntVar(&rate, "rate", 150, "Request rate hint")
	pflag.IntVar(&threads, "threads", 30, "Worker threads")
	pflag.IntVar(&limit, "limit", 50, "Output limit")
	pflag.StringVarP(&output, "output", "o", "", "Output file")
	pflag.BoolVarP(&quiet, "quiet", "q", false, "Quiet output")
	pflag.BoolVar(&showVersion, "version", false, "Show version")
	pflag.StringVar(&serveAddr, "addr", "127.0.0.1:8088", "Dashboard bind address")
	pflag.StringVar(&storagePath, "storage", "", "Storage root directory (default: ./storage)")
	pflag.StringVar(&stages, "stages", "all", "Comma-separated stages: subdomains,http,ports,urls,vulns")
	pflag.StringArrayVar(&setAPI, "set-api", nil, "Set API key as name=value (repeatable). Use empty value to unset.")
	pflag.BoolVar(&showAPI, "show-api", false, "Show configured API keys (masked)")
	pflag.BoolVar(&setup, "setup", false, "Show setup screen with tool installation status")
	pflag.BoolVar(&installTools, "install-tools", false, "Install missing supported tools (Linux)")
	pflag.StringVar(&profile, "profile", "balanced", "Workflow profile: passive|balanced|aggressive")
	pflag.BoolVar(&guide, "guide", false, "Show first-principles workflow guide")
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
		server := ui.New(application.Store)
		if err := server.Serve(serveAddr); err != nil {
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
	fmt.Println(`macaronV2 (Go stable rewrite)

Usage:
  macaron scan example.com
  macaron status
  macaron results -d example.com -w live
  macaron serve --addr 127.0.0.1:8088
  macaron setup

Core flags:
  -s, --scan TARGET      Scan one or more targets
  -F, --file FILE        Read targets from file
      --stdin            Read targets from stdin
  -m, --mode MODE        wide|narrow|fast|deep|osint
  -S, --status           Show scan summaries
  -R, --results          Show scan details
  -E, --export           Export JSON
  -L, --list-tools       Show tool availability
      --storage DIR       Use custom storage root (default ./storage)
      --stages LIST       Choose stages: subdomains,http,ports,urls,vulns
      --set-api k=v       Save API keys to storage config.yaml
      --show-api          Show masked API keys
      --setup             Show setup screen with tool status
      --install-tools     Install missing supported tools (Linux)
      --profile NAME      passive|balanced|aggressive
      --guide             Show first-principles workflow guide
      --serve            Start browser dashboard
      --version          Show version`)
}

func normalizeLegacyArgs() {
	for i, arg := range os.Args {
		if arg == "-setup" {
			os.Args[i] = "--setup"
		}
		if arg == "-install-tools" {
			os.Args[i] = "--install-tools"
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
			args = append(args, "--scan", tok)
		}
		if len(args) == 1 {
			args = append(args, "--scan")
		}
		os.Args = args
	case "status":
		os.Args = append([]string{os.Args[0], "--status"}, rest...)
	case "results":
		os.Args = append([]string{os.Args[0], "--results"}, rest...)
	case "serve":
		os.Args = append([]string{os.Args[0], "--serve"}, rest...)
	case "setup":
		os.Args = append([]string{os.Args[0], "--setup"}, rest...)
	case "export":
		os.Args = append([]string{os.Args[0], "--export"}, rest...)
	case "config":
		os.Args = append([]string{os.Args[0], "--config"}, rest...)
	case "guide":
		os.Args = append([]string{os.Args[0], "--guide"}, rest...)
	}
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
	fmt.Println(`macaronV2 guide (first-principles workflow)

1) Setup once:
   macaron setup
   macaron --install-tools
   macaron --set-api securitytrails=YOUR_KEY

2) Run intentional scans:
   macaron scan target.com --profile passive
   macaron scan target.com --profile balanced
   macaron scan target.com --profile aggressive --stages subdomains,http,ports,urls,vulns

3) Inspect and decide:
   macaron status
   macaron results -d target.com -w live
   macaron serve

4) Export/share:
   macaron export -o target.json

Profiles:
  passive    low-noise, low-rate, mostly passive collection
  balanced   default practical pipeline
  aggressive high concurrency for authorized deep testing only`)
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
