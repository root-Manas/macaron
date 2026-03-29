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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/root-Manas/macaron/internal/engine"
	"github.com/root-Manas/macaron/internal/model"
	"github.com/root-Manas/macaron/internal/store"
)

var toolNames = []string{"subfinder", "assetfinder", "findomain", "nuclei"}

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
		return "No scans found. Run: macaron -s example.com", nil
	}
	b := strings.Builder{}
	b.WriteString("macaronV2 status\n")
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
