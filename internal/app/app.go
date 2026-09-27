package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/root-Manas/macaron/internal/engine"
	"github.com/root-Manas/macaron/internal/model"
	"github.com/root-Manas/macaron/internal/store"
)

var toolNames = []string{
	"subfinder", "assetfinder", "findomain", "amass",
	"nuclei", "httpx", "dnsx", "naabu",
	"gau", "waybackurls", "katana",
	"ffuf", "gobuster", "feroxbuster",
	"gospider", "hakrawler",
}

type SetupTool struct {
	Name          string
	Binary        string
	Required      bool
	Installed     bool
	InstallMethod string
	InstallCmd    string
}

type App struct {
	Store  *store.Store
	Engine *engine.Engine
	Home   string
}

type ScanArgs struct {
	Targets       []string
	Mode          model.Mode
	Rate          int
	Threads       int
	TargetWorkers int
	Quiet         bool
	EnabledStages map[string]bool
	APIKeys       map[string]string
	Progress      func(model.StageEvent)
}

func New(home string) (*App, error) {
	st, err := store.New(home)
	if err != nil {
		return nil, err
	}
	return &App{Store: st, Engine: engine.New(), Home: home}, nil
}

func (a *App) Scan(ctx context.Context, args ScanArgs) ([]model.ScanResult, error) {
	if len(args.Targets) == 0 {
		return nil, errors.New("no valid targets provided")
	}
	workers := args.TargetWorkers
	if workers <= 0 {
		workers = 1
	}
	if workers > len(args.Targets) {
		workers = len(args.Targets)
	}

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make([]model.ScanResult, len(args.Targets))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex

	worker := func() {
		defer wg.Done()
		for index := range jobs {
			if scanCtx.Err() != nil {
				return
			}
			target := args.Targets[index]
			res, err := a.Engine.ScanTarget(scanCtx, target, engine.Options{
				Mode:          args.Mode,
				Rate:          args.Rate,
				Threads:       args.Threads,
				Quiet:         args.Quiet,
				EnabledStages: args.EnabledStages,
				APIKeys:       args.APIKeys,
				Progress:      args.Progress,
			})
			if err == nil {
				err = a.Store.SaveScan(res)
			}
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("scan %s: %w", target, err)
					cancel()
				}
				errMu.Unlock()
				return
			}
			results[index] = res
		}
	}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}
	for index := range args.Targets {
		select {
		case jobs <- index:
		case <-scanCtx.Done():
			break
		}
		if scanCtx.Err() != nil {
			break
		}
	}
	close(jobs)
	wg.Wait()

	errMu.Lock()
	err := firstErr
	errMu.Unlock()
	if err != nil {
		return compactResults(results), err
	}
	return results, nil
}

func compactResults(results []model.ScanResult) []model.ScanResult {
	out := make([]model.ScanResult, 0, len(results))
	for _, result := range results {
		if result.ID != "" {
			out = append(out, result)
		}
	}
	return out
}

func (a *App) ShowStatus(limit int) (string, error) {
	summaries, err := a.Store.Summaries(limit)
	if err != nil {
		return "", err
	}
	if len(summaries) == 0 {
		return "no scans on record. run: macaron scan <target>", nil
	}
	b := strings.Builder{}
	b.WriteString("scan history\n")
	tw := table.NewWriter()
	tw.AppendHeader(table.Row{"ID", "TARGET", "MODE", "LIVE", "URLS", "VULNS", "FINISHED"})
	for _, s := range summaries {
		tw.AppendRow(table.Row{
			s.ID,
			s.Target,
			s.Mode,
			strconv.Itoa(s.Stats.LiveHosts),
			strconv.Itoa(s.Stats.URLs),
			strconv.Itoa(s.Stats.Vulns),
			s.FinishedAt.Format(time.RFC3339),
		})
	}
	b.WriteString(tw.Render())
	b.WriteString("\n")
	return b.String(), nil
}

func (a *App) ShowStatusJSON(limit int) (string, error) {
	summaries, err := a.Store.Summaries(limit)
	if err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(summaries, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

func (a *App) ShowResults(target string, id string, what string, limit int) (string, error) {
	what = strings.ToLower(strings.TrimSpace(what))
	if what == "" {
		what = "all"
	}
	switch what {
	case "all", "subdomains", "live", "ports", "urls", "js", "vulns":
	default:
		return "", fmt.Errorf("unknown result view %q", what)
	}
	var res *model.ScanResult
	var err error
	if id != "" {
		res, err = a.Store.GetByID(id)
	} else if target != "" {
		res, err = a.Store.LatestByTarget(target)
	} else {
		summaries, errS := a.Store.Summaries(1)
		if errS != nil || len(summaries) == 0 {
			return "", errors.New("no scans found")
		}
		res, err = a.Store.GetByID(summaries[0].ID)
	}
	if err != nil {
		return "", err
	}
	if limit <= 0 {
		limit = 50
	}
	return formatResults(*res, what, limit), nil
}

func (a *App) ShowResultsJSON(target string, id string) (string, error) {
	var res *model.ScanResult
	var err error
	if id != "" {
		res, err = a.Store.GetByID(id)
	} else if target != "" {
		res, err = a.Store.LatestByTarget(target)
	} else {
		summaries, errS := a.Store.Summaries(1)
		if errS != nil {
			return "", errS
		}
		if len(summaries) == 0 {
			return "", errors.New("no scans found")
		}
		res, err = a.Store.GetByID(summaries[0].ID)
	}
	if err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

func (a *App) Export(path, target string) (string, error) {
	return a.Store.Export(path, target)
}

func (a *App) ShowConfig() string {
	return fmt.Sprintf(
		"Storage: %s\nDB: %s\nConfig: %s\nPer-target folders: %s\n",
		a.Home,
		filepath.Join(a.Home, "macaron.db"),
		filepath.Join(a.Home, "config.yaml"),
		filepath.Join(a.Home, "<target>"),
	)
}

func ParseTargets(raw []string, filePath string, stdin bool) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	invalid := make([]string, 0)
	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" || strings.HasPrefix(t, "#") {
			return
		}
		if !validTargetInput(t) {
			invalid = append(invalid, "invalid target")
			return
		}
		t = normalizeTarget(t)
		if t == "" {
			invalid = append(invalid, "invalid target")
			return
		}
		if _, ok := seen[t]; ok {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	for _, t := range raw {
		add(t)
	}
	if filePath != "" {
		b, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			add(line)
		}
	}
	if stdin {
		b, err := ioReadAllStdin()
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			add(line)
		}
	}
	if len(invalid) > 0 {
		return nil, fmt.Errorf("one or more targets are invalid (expected a domain, IP, or bare origin URL)")
	}
	sort.Strings(out)
	return out, nil
}

func formatResults(res model.ScanResult, what string, limit int) string {
	b := strings.Builder{}
	b.WriteString(fmt.Sprintf("Scan: %s (%s)\n", res.Target, res.ID))
	b.WriteString(fmt.Sprintf("Mode: %s  Duration: %dms\n", res.Mode, res.DurationMS))
	b.WriteString(fmt.Sprintf("Stats: subdomains=%d live=%d ports=%d urls=%d js=%d vulns=%d\n\n",
		res.Stats.Subdomains, res.Stats.LiveHosts, res.Stats.Ports, res.Stats.URLs, res.Stats.JSFiles, res.Stats.Vulns,
	))

	switch what {
	case "subdomains":
		for _, v := range firstN(res.Subdomains, limit) {
			b.WriteString(v + "\n")
		}
	case "live":
		for _, v := range firstNLive(res.LiveHosts, limit) {
			b.WriteString(fmt.Sprintf("%d %s %s\n", v.StatusCode, v.URL, v.Title))
		}
	case "ports":
		for _, v := range firstNPorts(res.Ports, limit) {
			b.WriteString(fmt.Sprintf("%s:%d\n", v.Host, v.Port))
		}
	case "urls":
		for _, v := range firstN(res.URLs, limit) {
			b.WriteString(v + "\n")
		}
	case "js":
		for _, v := range firstN(res.JSFiles, limit) {
			b.WriteString(v + "\n")
		}
	case "vulns":
		for _, v := range firstNVulns(res.Vulns, limit) {
			b.WriteString(fmt.Sprintf("[%s] %s -> %s\n", v.Severity, v.Template, v.Matched))
		}
	default:
		enc, _ := json.MarshalIndent(res, "", "  ")
		b.WriteString(string(enc) + "\n")
	}
	return b.String()
}

func ListTools() []model.ToolStatus {
	items := make([]model.ToolStatus, 0, len(toolNames))
	for _, t := range toolNames {
		_, err := execLookPath(t)
		items = append(items, model.ToolStatus{Name: t, Installed: err == nil})
	}
	return items
}

func SetupCatalog() []SetupTool {
	tools := []SetupTool{
		// Subdomain enumeration
		{Name: "subfinder", Binary: "subfinder", Required: true, InstallMethod: "go", InstallCmd: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
		{Name: "assetfinder", Binary: "assetfinder", Required: true, InstallMethod: "go", InstallCmd: "go install github.com/tomnomnom/assetfinder@latest"},
		{Name: "findomain", Binary: "findomain", Required: false, InstallMethod: "manual", InstallCmd: "https://github.com/Findomain/Findomain/releases"},
		{Name: "amass", Binary: "amass", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/owasp-amass/amass/v4/...@master"},
		// HTTP probing & tech detection
		{Name: "httpx", Binary: "httpx", Required: true, InstallMethod: "go", InstallCmd: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"},
		// DNS resolution & brute
		{Name: "dnsx", Binary: "dnsx", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
		// Port scanning
		{Name: "naabu", Binary: "naabu", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
		// URL discovery (passive)
		{Name: "gau", Binary: "gau", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/lc/gau/v2/cmd/gau@latest"},
		{Name: "waybackurls", Binary: "waybackurls", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/tomnomnom/waybackurls@latest"},
		// Active crawling
		{Name: "katana", Binary: "katana", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
		{Name: "gospider", Binary: "gospider", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/jaeles-project/gospider@latest"},
		{Name: "hakrawler", Binary: "hakrawler", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/hakluke/hakrawler@latest"},
		// Content discovery / fuzzing
		{Name: "ffuf", Binary: "ffuf", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/ffuf/ffuf/v2@latest"},
		{Name: "gobuster", Binary: "gobuster", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/OJ/gobuster/v3@latest"},
		{Name: "feroxbuster", Binary: "feroxbuster", Required: false, InstallMethod: "manual", InstallCmd: "https://github.com/epi052/feroxbuster/releases"},
		// Vulnerability scanning
		{Name: "nuclei", Binary: "nuclei", Required: true, InstallMethod: "go", InstallCmd: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
	}
	for i := range tools {
		_, err := execLookPath(tools[i].Binary)
		tools[i].Installed = err == nil
	}
	return tools
}

func RenderSetup(tools []SetupTool) string {
	tw := table.NewWriter()
	tw.AppendHeader(table.Row{"TOOL", "ROLE", "REQUIRED", "STATUS", "INSTALL"})

	roleMap := map[string]string{
		"subfinder":   "subdomain enum",
		"assetfinder": "subdomain enum",
		"findomain":   "subdomain enum",
		"amass":       "subdomain enum",
		"httpx":       "http probe",
		"dnsx":        "dns resolve",
		"naabu":       "port scan",
		"gau":         "url discovery",
		"waybackurls": "url discovery",
		"katana":      "active crawl",
		"gospider":    "active crawl",
		"hakrawler":   "active crawl",
		"ffuf":        "content fuzz",
		"gobuster":    "content fuzz",
		"feroxbuster": "content fuzz",
		"nuclei":      "vuln scan",
	}

	for _, t := range tools {
		required := "optional"
		if t.Required {
			required = "required"
		}
		status := "missing"
		if t.Installed {
			status = "installed"
		}
		tw.AppendRow(table.Row{t.Name, roleMap[t.Name], required, status, t.InstallCmd})
	}
	b := strings.Builder{}
	b.WriteString("tool inventory\n")
	b.WriteString(tw.Render())
	b.WriteString("\n")
	return b.String()
}

func InstallMissingTools(ctx context.Context, tools []SetupTool) ([]string, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("auto-install is currently supported on Linux only")
	}
	installed := make([]string, 0, 8)
	for _, t := range tools {
		if t.Installed || t.InstallMethod != "go" {
			continue
		}
		cmd := exec.CommandContext(ctx, "sh", "-lc", t.InstallCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return installed, fmt.Errorf("%s install failed: %v (%s)", t.Name, err, strings.TrimSpace(string(out)))
		}
		installed = append(installed, t.Name)
	}
	return installed, nil
}

func RenderScanSummary(results []model.ScanResult) string {
	tw := table.NewWriter()
	tw.AppendHeader(table.Row{"TARGET", "MODE", "SUBDOMAINS", "LIVE", "URLS", "VULNS", "DURATION"})
	for _, r := range results {
		tw.AppendRow(table.Row{
			r.Target,
			r.Mode,
			r.Stats.Subdomains,
			r.Stats.LiveHosts,
			r.Stats.URLs,
			r.Stats.Vulns,
			fmt.Sprintf("%dms", r.DurationMS),
		})
	}
	return tw.Render()
}

func execLookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func ioReadAllStdin() ([]byte, error) {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Mode()&os.ModeCharDevice != 0 {
		return nil, errors.New("stdin empty")
	}
	return io.ReadAll(os.Stdin)
}

func normalizeTarget(t string) string {
	t = strings.TrimSpace(strings.ToLower(t))
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimPrefix(t, "http://")
	if i := strings.IndexRune(t, '/'); i > -1 {
		t = t[:i]
	}
	if i := strings.IndexRune(t, ':'); i > -1 {
		t = t[:i]
	}
	return t
}

func validTargetInput(raw string) bool {
	value := strings.TrimSpace(raw)
	if strings.Contains(value, "://") {
		u, err := url.Parse(value)
		if err != nil || (strings.ToLower(u.Scheme) != "http" && strings.ToLower(u.Scheme) != "https") || u.User != nil || u.Port() != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return false
		}
		value = u.Hostname()
	} else if strings.ContainsAny(value, "/?#@") || (strings.Contains(value, ":") && net.ParseIP(value) == nil) {
		return false
	}
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if net.ParseIP(value) != nil {
		return true
	}
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func firstN(items []string, n int) []string {
	if n <= 0 || len(items) <= n {
		return items
	}
	return items[:n]
}

func firstNLive(items []model.LiveHost, n int) []model.LiveHost {
	if n <= 0 || len(items) <= n {
		return items
	}
	return items[:n]
}

func firstNPorts(items []model.PortHit, n int) []model.PortHit {
	if n <= 0 || len(items) <= n {
		return items
	}
	return items[:n]
}

func firstNVulns(items []model.Vulnerability, n int) []model.Vulnerability {
	if n <= 0 || len(items) <= n {
		return items
	}
	return items[:n]
}

func ParseStages(raw string) map[string]bool {
	all := []string{"subdomains", "http", "ports", "urls", "vulns"}
	if strings.TrimSpace(raw) == "" || strings.EqualFold(strings.TrimSpace(raw), "all") {
		m := make(map[string]bool, len(all))
		for _, s := range all {
			m[s] = true
		}
		return m
	}
	out := make(map[string]bool, len(all))
	for _, s := range strings.Split(raw, ",") {
		v := strings.ToLower(strings.TrimSpace(s))
		if v == "" {
			continue
		}
		out[v] = true
	}
	return out
}
