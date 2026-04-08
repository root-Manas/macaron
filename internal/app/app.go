package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/root-Manas/macaron/internal/engine"
	"github.com/root-Manas/macaron/internal/model"
	"github.com/root-Manas/macaron/internal/store"
)

var toolNames = []string{"subfinder", "assetfinder", "findomain", "nuclei"}

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
	results := make([]model.ScanResult, 0, len(args.Targets))
	for _, t := range args.Targets {
		res, err := a.Engine.ScanTarget(ctx, t, engine.Options{
			Mode:          args.Mode,
			Rate:          args.Rate,
			Threads:       args.Threads,
			Quiet:         args.Quiet,
			EnabledStages: args.EnabledStages,
			APIKeys:       args.APIKeys,
			Progress:      args.Progress,
		})
		if err != nil {
			return nil, err
		}
		if err := a.Store.SaveScan(res); err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}

func (a *App) ShowStatus(limit int) (string, error) {
	summaries, err := a.Store.Summaries(limit)
	if err != nil {
		return "", err
	}
	if len(summaries) == 0 {
		return "No scans found.\nRun: macaron scan example.com\n", nil
	}
	b := strings.Builder{}
	b.WriteString("macaron status\n")
	tw := table.NewWriter()
	tw.AppendHeader(table.Row{"ID", "TARGET", "MODE", "SUBS", "LIVE", "PORTS", "URLS", "VULNS", "FINISHED"})
	for _, s := range summaries {
		shortID := s.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		tw.AppendRow(table.Row{
			shortID,
			s.Target,
			s.Mode,
			strconv.Itoa(s.Stats.Subdomains),
			strconv.Itoa(s.Stats.LiveHosts),
			strconv.Itoa(s.Stats.Ports),
			strconv.Itoa(s.Stats.URLs),
			strconv.Itoa(s.Stats.Vulns),
			s.FinishedAt.Format("2006-01-02 15:04"),
		})
	}
	b.WriteString(tw.Render())
	b.WriteString("\n")
	return b.String(), nil
}

func (a *App) ShowResults(target string, id string, what string, limit int) (string, error) {
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
	return formatResults(*res, strings.ToLower(what), limit), nil
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
	add := func(t string) {
		t = normalizeTarget(t)
		if t == "" {
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
		if err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				add(line)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func formatResults(res model.ScanResult, what string, limit int) string {
	b := strings.Builder{}
	b.WriteString(fmt.Sprintf("target: %s  id: %s\n", res.Target, res.ID))
	b.WriteString(fmt.Sprintf("mode: %s  duration: %dms\n", res.Mode, res.DurationMS))
	b.WriteString(fmt.Sprintf("subdomains: %d  live: %d  ports: %d  urls: %d  js: %d  vulns: %d\n\n",
		res.Stats.Subdomains, res.Stats.LiveHosts, res.Stats.Ports, res.Stats.URLs, res.Stats.JSFiles, res.Stats.Vulns,
	))

	switch what {
	case "subdomains":
		for _, v := range firstN(res.Subdomains, limit) {
			b.WriteString(v + "\n")
		}
	case "live":
		tw := table.NewWriter()
		tw.AppendHeader(table.Row{"STATUS", "URL", "TITLE"})
		for _, v := range firstNLive(res.LiveHosts, limit) {
			tw.AppendRow(table.Row{v.StatusCode, v.URL, v.Title})
		}
		b.WriteString(tw.Render())
		b.WriteString("\n")
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
		tw := table.NewWriter()
		tw.AppendHeader(table.Row{"SEVERITY", "TEMPLATE", "MATCHED"})
		for _, v := range firstNVulns(res.Vulns, limit) {
			tw.AppendRow(table.Row{strings.ToUpper(v.Severity), v.Template, v.Matched})
		}
		b.WriteString(tw.Render())
		b.WriteString("\n")
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
		{Name: "subfinder", Binary: "subfinder", Required: true, InstallMethod: "go", InstallCmd: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
		{Name: "assetfinder", Binary: "assetfinder", Required: true, InstallMethod: "go", InstallCmd: "go install github.com/tomnomnom/assetfinder@latest"},
		{Name: "findomain", Binary: "findomain", Required: false, InstallMethod: "manual", InstallCmd: "apt install findomain OR download release binary"},
		{Name: "nuclei", Binary: "nuclei", Required: true, InstallMethod: "go", InstallCmd: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
		{Name: "httpx", Binary: "httpx", Required: true, InstallMethod: "go", InstallCmd: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"},
		{Name: "dnsx", Binary: "dnsx", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
		{Name: "naabu", Binary: "naabu", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
		{Name: "gau", Binary: "gau", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/lc/gau/v2/cmd/gau@latest"},
		{Name: "waybackurls", Binary: "waybackurls", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/tomnomnom/waybackurls@latest"},
		{Name: "katana", Binary: "katana", Required: false, InstallMethod: "go", InstallCmd: "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
	}
	for i := range tools {
		_, err := execLookPath(tools[i].Binary)
		tools[i].Installed = err == nil
	}
	return tools
}

func RenderSetup(tools []SetupTool) string {
	tw := table.NewWriter()
	tw.AppendHeader(table.Row{"TOOL", "REQUIRED", "STATUS", "INSTALL COMMAND"})
	installedCount := 0
	for _, t := range tools {
		required := "no"
		if t.Required {
			required = "yes"
		}
		status := "missing"
		if t.Installed {
			status = "ok"
			installedCount++
		}
		tw.AppendRow(table.Row{t.Name, required, status, t.InstallCmd})
	}
	b := strings.Builder{}
	b.WriteString("macaron setup\n")
	b.WriteString(tw.Render())
	b.WriteString(fmt.Sprintf("\n%d / %d tools installed\n", installedCount, len(tools)))
	missing := 0
	for _, t := range tools {
		if t.Required && !t.Installed {
			missing++
		}
	}
	if missing > 0 {
		b.WriteString(fmt.Sprintf("\n%d required tool(s) missing. Run: macaron --ins\n", missing))
	} else {
		b.WriteString("\nAll required tools are installed.\n")
		b.WriteString("\nNext steps:\n")
		b.WriteString("  macaron scan example.com\n")
		b.WriteString("  macaron status\n")
		b.WriteString("  macaron serve\n")
	}
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
