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
		noColor      bool
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
	pflag.BoolVar(&quiet, "qut", false, "Quiet output (no banner, no progress)")
	pflag.BoolVar(&noColor, "nc", false, "Disable color output")
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

	if noColor {
		os.Setenv("NO_COLOR", "1")
	}

	if showVersion {
		cliui.PrintBanner(version, false)
		fmt.Printf("macaronV2 %s (Go %s, stable)\n", version, runtime.Version())
		return 0
	}
	if guide {
		cliui.PrintBanner(version, quiet)
		printGuide()
		return 0
	}

	home, err := macaronHome(storagePath)
	if err != nil {
		cliui.Err("storage: %v", err)
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
	if len(setAPI) > 0 {
		cfg.ApplySetAPI(config, setAPI)
		if err := cfg.Save(home, config); err != nil {
			cliui.Err("saving config: %v", err)
			return 1
		}
		cliui.OK("API keys saved → %s", filepath.Join(home, "config.yaml"))
		return 0
	}
	if showAPI {
		items := cfg.MaskedKeys(config)
		if len(items) == 0 {
			cliui.Info("No API keys configured")
			return 0
		}
		cliui.Info("Configured API keys:")
		for _, item := range items {
			fmt.Printf("  %s %s\n", cliui.CyanText("•"), item)
		}
		return 0
	}
	if setup || installTools {
		cliui.PrintBanner(version, quiet)
		tools := app.SetupCatalog()
		fmt.Print(app.RenderSetup(tools))
		if installTools {
			cliui.Info("Installing missing tools…")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			installed, err := app.InstallMissingTools(ctx, tools)
			if err != nil {
				cliui.Err("setup: %v", err)
				return 1
			}
			if len(installed) == 0 {
				cliui.Info("No installable missing tools found.")
			} else {
				cliui.OK("Installed: %s", strings.Join(installed, ", "))
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
		cliui.Info("Pipeline (macaronV2 native): %s", filepath.Join(home, "pipeline.v2.yaml"))
		return 0
	}
	if listTools {
		cliui.PrintBanner(version, quiet)
		for _, t := range app.ListTools() {
			if t.Installed {
				fmt.Printf("  %s %-14s %s\n", cliui.GreenText("✔"), t.Name, cliui.Muted("installed"))
			} else {
				fmt.Printf("  %s %-14s %s\n", cliui.YellowText("✘"), t.Name, cliui.Muted("missing"))
			}
		}
		return 0
	}
	if status {
		cliui.PrintBanner(version, quiet)
		out, err := application.ShowStatus(limit)
		if err != nil {
			cliui.Err("%v", err)
			return 1
		}
		fmt.Print(out)
		return 0
	}
	if results {
		out, err := application.ShowResults(domain, scanID, what, limit)
		if err != nil {
			cliui.Err("%v", err)
			return 1
		}
		fmt.Print(out)
		return 0
	}
	if export {
		path, err := application.Export(output, domain)
		if err != nil {
			cliui.Err("%v", err)
			return 1
		}
		cliui.OK("Exported → %s", path)
		return 0
	}
	if serve {
		cliui.PrintBanner(version, quiet)
		cliui.Info("Starting dashboard on http://%s", serveAddr)
		server := ui.New(application.Store)
		if err := server.Serve(serveAddr); err != nil {
			cliui.Err("%v", err)
			return 1
		}
		return 0
	}

	targets, err := app.ParseTargets(scanTargets, filePath, useStdin)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		cliui.Err("%v", err)
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
		cliui.Err("--rte (rate) must be > 0")
		return 1
	}
	if threads <= 0 {
		cliui.Err("--thr (threads) must be > 0")
		return 1
	}

	cliui.PrintBanner(version, quiet)
	if !quiet {
		cliui.Info("Profile: %s | mode: %s | stages: %s | rate: %d | threads: %d",
			cliui.Highlight(profile), cliui.Highlight(mode),
			cliui.Highlight(stages), rate, threads)
		for _, t := range targets {
			cliui.Info("Target: %s", cliui.Highlight(t))
		}
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
		cliui.Err("scan failed: %v", err)
		return 1
	}
	if !quiet {
		elapsed := time.Since(start).Round(time.Millisecond)
		cliui.OK("Completed %d target(s) in %s", len(res), elapsed)
		fmt.Println()
		fmt.Println(app.RenderScanSummary(res))
	}
	return 0
}

func printHelp() {
	c := cliui.CyanText
	b := cliui.Highlight
	m := cliui.Muted

	cliui.PrintBanner(version, false)
	fmt.Printf("%s\n", b("USAGE"))
	fmt.Printf("  macaron %s example.com\n", c("scan"))
	fmt.Printf("  macaron %s\n", c("status"))
	fmt.Printf("  macaron %s -dom example.com -wht live\n", c("results"))
	fmt.Printf("  macaron %s -adr 127.0.0.1:8088\n", c("serve"))
	fmt.Printf("  macaron %s\n", c("setup"))
	fmt.Printf("  macaron %s -out results.json\n\n", c("export"))

	fmt.Printf("%s\n", b("SCAN FLAGS"))
	fmt.Printf("  %s TARGET   %s\n", c("-scn"), m("Scan one or more targets (repeatable)"))
	fmt.Printf("  %s FILE     %s\n", c("-fil"), m("Read targets from file"))
	fmt.Printf("  %s          %s\n", c("-inp"), m("Read targets from stdin"))
	fmt.Printf("  %s MODE     %s\n", c("-mod"), m("Scan mode: wide|narrow|fast|deep|osint"))
	fmt.Printf("  %s LIST     %s\n", c("-stg"), m("Stages: subdomains,http,ports,urls,vulns"))
	fmt.Printf("  %s NAME     %s\n", c("-prf"), m("Profile: passive|balanced|aggressive"))
	fmt.Printf("  %s N        %s\n", c("-rte"), m("Request rate hint (default: 150)"))
	fmt.Printf("  %s N        %s\n\n", c("-thr"), m("Worker threads (default: 30)"))

	fmt.Printf("%s\n", b("OUTPUT FLAGS"))
	fmt.Printf("  %s          %s\n", c("-sts"), m("Show recent scan summaries"))
	fmt.Printf("  %s          %s\n", c("-res"), m("Show scan results"))
	fmt.Printf("  %s DOMAIN   %s\n", c("-dom"), m("Filter by domain"))
	fmt.Printf("  %s ID       %s\n", c("-sid"), m("Fetch specific scan ID"))
	fmt.Printf("  %s TYPE     %s\n", c("-wht"), m("Result view: all|subdomains|live|ports|urls|js|vulns"))
	fmt.Printf("  %s N        %s\n", c("-lim"), m("Output limit (default: 50)"))
	fmt.Printf("  %s FILE     %s\n", c("-out"), m("Output file for export"))
	fmt.Printf("  %s          %s\n", c("-exp"), m("Export results to JSON"))
	fmt.Printf("  %s          %s\n\n", c("-qut"), m("Quiet mode (suppress banner and progress)"))

	fmt.Printf("%s\n", b("API KEYS"))
	fmt.Printf("  %s k=v      %s\n", c("-sak"), m("Set API key (e.g. -sak securitytrails=KEY)"))
	fmt.Printf("  %s          %s\n\n", c("-shk"), m("Show masked API keys"))

	fmt.Printf("%s\n", b("DASHBOARD"))
	fmt.Printf("  %s          %s\n", c("-srv"), m("Start browser dashboard"))
	fmt.Printf("  %s ADDR     %s\n\n", c("-adr"), m("Bind address (default: 127.0.0.1:8088)"))

	fmt.Printf("%s\n", b("TOOLS & CONFIG"))
	fmt.Printf("  %s          %s\n", c("-stp"), m("Show tool installation status"))
	fmt.Printf("  %s          %s\n", c("-ins"), m("Install missing supported tools (Linux)"))
	fmt.Printf("  %s          %s\n", c("-lst"), m("List external tool availability"))
	fmt.Printf("  %s DIR      %s\n", c("-str"), m("Custom storage root (default: ./storage)"))
	fmt.Printf("  %s          %s\n", c("-cfg"), m("Show config paths"))
	fmt.Printf("  %s          %s\n", c("-gud"), m("Show first-principles workflow guide"))
	fmt.Printf("  %s          %s\n", c("-nc"),  m("Disable color output"))
	fmt.Printf("  %s          %s\n\n", c("-ver"), m("Show version"))

	fmt.Printf("%s\n", b("EXAMPLES"))
	fmt.Printf("  %s\n", m("# Passive OSINT scan"))
	fmt.Printf("  macaron scan example.com %s passive\n\n", c("-prf"))
	fmt.Printf("  %s\n", m("# Aggressive full scan"))
	fmt.Printf("  macaron scan example.com %s aggressive %s subdomains,http,ports,urls,vulns\n\n", c("-prf"), c("-stg"))
	fmt.Printf("  %s\n", m("# View live hosts from last scan"))
	fmt.Printf("  macaron results %s example.com %s live\n\n", c("-dom"), c("-wht"))
	fmt.Printf("  %s\n", m("# Use API key for better coverage"))
	fmt.Printf("  macaron %s securitytrails=YOUR_KEY\n\n", c("-sak"))
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
		if len(args) == 1 {
			args = append(args, "--scn")
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
		"no-color": "nc", "nc": "nc",
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
	b := cliui.Highlight
	c := cliui.CyanText
	m := cliui.Muted
	g := cliui.GreenText

	fmt.Printf("%s\n\n", b("WORKFLOW GUIDE — first principles"))

	fmt.Printf("%s  %s\n", g("1)"), b("Setup once"))
	fmt.Printf("   macaron %s\n", c("setup"))
	fmt.Printf("   macaron %s\n", c("-ins"))
	fmt.Printf("   macaron %s securitytrails=YOUR_KEY\n\n", c("-sak"))

	fmt.Printf("%s  %s\n", g("2)"), b("Run intentional scans"))
	fmt.Printf("   macaron scan target.com %s passive\n", c("-prf"))
	fmt.Printf("   macaron scan target.com %s balanced\n", c("-prf"))
	fmt.Printf("   macaron scan target.com %s aggressive %s subdomains,http,ports,urls,vulns\n\n", c("-prf"), c("-stg"))

	fmt.Printf("%s  %s\n", g("3)"), b("Inspect and decide"))
	fmt.Printf("   macaron %s\n", c("status"))
	fmt.Printf("   macaron %s %s target.com %s live\n", c("results"), c("-dom"), c("-wht"))
	fmt.Printf("   macaron %s\n\n", c("serve"))

	fmt.Printf("%s  %s\n", g("4)"), b("Export / share"))
	fmt.Printf("   macaron %s %s target.json\n\n", c("export"), c("-out"))

	fmt.Printf("%s\n", b("PROFILES"))
	fmt.Printf("  %s   %s\n", c("passive"),    m("low-noise, low-rate, mostly passive collection"))
	fmt.Printf("  %s  %s\n", c("balanced"),   m("default practical pipeline"))
	fmt.Printf("  %s %s\n\n", c("aggressive"), m("high concurrency for authorized deep testing only"))
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
