package engine

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/root-Manas/macaron/internal/model"
)

type Options struct {
	Mode    model.Mode
	Rate    int
	Threads int
	Quiet   bool
}

type Engine struct {
	httpClient *http.Client
}

func New() *Engine {
	transport := &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 20,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
	}
	return &Engine{
		httpClient: &http.Client{Timeout: 12 * time.Second, Transport: transport},
	}
}

func (e *Engine) ScanTarget(ctx context.Context, target string, opts Options) (model.ScanResult, error) {
	start := time.Now()
	result := model.ScanResult{
		ID:        fmt.Sprintf("%s-%d", sanitizeTarget(target), start.Unix()),
		Target:    normalizeTarget(target),
		Mode:      normalizeMode(opts.Mode),
		StartedAt: start,
	}
	if opts.Threads <= 0 {
		opts.Threads = 30
	}
	if opts.Rate <= 0 {
		opts.Rate = 150
	}

	subs := map[string]struct{}{result.Target: {}}

	nativeSubs, warn := e.crtshSubdomains(ctx, result.Target)
	if warn != "" {
		result.Warnings = append(result.Warnings, warn)
	}
	for _, s := range nativeSubs {
		if looksLikeHost(s) {
			subs[s] = struct{}{}
		}
	}

	for _, tool := range []string{"subfinder", "assetfinder", "findomain"} {
		lines, err := runSubdomainTool(ctx, tool, result.Target, opts.Threads)
		if err != nil {
			continue
		}
		for _, line := range lines {
			s := normalizeTarget(line)
			if s != "" && strings.Contains(s, result.Target) && looksLikeHost(s) {
				subs[s] = struct{}{}
			}
		}
	}

	result.Subdomains = mapKeys(subs)

	probeInputs := result.Subdomains
	if result.Mode == model.ModeNarrow {
		probeInputs = []string{result.Target}
	}

	live := e.probeHTTP(ctx, probeInputs, opts.Threads)
	result.LiveHosts = live

	ports := scanCommonPorts(probeInputs, opts.Threads)
	result.Ports = ports

	urls := e.discoverURLs(ctx, probeInputs, opts.Threads)
	result.URLs = urls
	result.JSFiles = extractJS(urls)

	if hasBinary("nuclei") {
		vulns, err := runNuclei(ctx, live)
		if err == nil {
			result.Vulns = vulns
		}
	} else {
		result.Warnings = append(result.Warnings, "nuclei not installed: vulnerability stage skipped")
	}

	result.Stats = model.ScanStats{
		Subdomains: len(result.Subdomains),
		LiveHosts:  len(result.LiveHosts),
		Ports:      len(result.Ports),
		URLs:       len(result.URLs),
		JSFiles:    len(result.JSFiles),
		Vulns:      len(result.Vulns),
	}
	result.FinishedAt = time.Now()
	result.DurationMS = result.FinishedAt.Sub(start).Milliseconds()
	return result, nil
}

func normalizeMode(m model.Mode) model.Mode {
	switch m {
	case model.ModeFast, model.ModeNarrow, model.ModeWide, model.ModeDeep, model.ModeOSINT:
		return m
	default:
		return model.ModeWide
	}
}

func hasBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func runSubdomainTool(ctx context.Context, tool string, target string, threads int) ([]string, error) {
	if !hasBinary(tool) {
		return nil, fmt.Errorf("%s missing", tool)
	}
	cmdline := ""
	switch tool {
	case "subfinder":
		cmdline = fmt.Sprintf("subfinder -d %s -silent -all -t %d", shellEscape(target), threads)
	case "assetfinder":
		cmdline = fmt.Sprintf("assetfinder --subs-only %s", shellEscape(target))
	case "findomain":
		cmdline = fmt.Sprintf("findomain -t %s -q", shellEscape(target))
	default:
		return nil, fmt.Errorf("unsupported tool")
	}
	return runLines(ctx, cmdline, 4*time.Minute)
}

func runLines(parent context.Context, cmdline string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := shellCommand(ctx, cmdline)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := make([]string, 0, 256)
	s := bufio.NewScanner(strings.NewReader(string(out)))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return dedupe(lines), nil
}

func shellCommand(ctx context.Context, cmdline string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", cmdline)
	}
	return exec.CommandContext(ctx, "sh", "-c", cmdline)
}

func shellEscape(s string) string {
	return strings.ReplaceAll(s, "'", "")
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

func sanitizeTarget(t string) string {
	t = normalizeTarget(t)
	re := regexp.MustCompile(`[^a-z0-9.-]`)
	return re.ReplaceAllString(t, "_")
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func (e *Engine) crtshSubdomains(ctx context.Context, target string) ([]string, string) {
	u := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(target))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "crt.sh request failed"
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, "crt.sh lookup failed"
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, "crt.sh returned non-2xx"
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, "crt.sh read failed"
	}
	if len(body) == 0 {
		return nil, ""
	}
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, "crt.sh parse failed"
	}
	items := make([]string, 0, len(rows)*2)
	for _, row := range rows {
		name, _ := row["name_value"].(string)
		for _, s := range strings.Split(name, "\n") {
			s = strings.TrimSpace(strings.TrimPrefix(s, "*."))
			s = normalizeTarget(s)
			if s != "" && strings.HasSuffix(s, target) {
				items = append(items, s)
			}
		}
	}
	return dedupe(items), ""
}

func (e *Engine) probeHTTP(ctx context.Context, hosts []string, threads int) []model.LiveHost {
	jobs := make(chan string)
	results := make(chan model.LiveHost, len(hosts))
	wg := sync.WaitGroup{}
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				if !looksLikeHost(host) {
					continue
				}
				for _, scheme := range []string{"https", "http"} {
					u := fmt.Sprintf("%s://%s", scheme, host)
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
					if err != nil {
						continue
					}
					resp, err := e.httpClient.Do(req)
					if err != nil {
						continue
					}
					title := extractTitle(resp.Body)
					_ = resp.Body.Close()
					results <- model.LiveHost{URL: u, StatusCode: resp.StatusCode, Title: title, Tech: resp.Header.Get("Server")}
					break
				}
			}
		}()
	}
	for _, host := range dedupe(hosts) {
		jobs <- host
	}
	close(jobs)
	wg.Wait()
	close(results)

	out := make([]model.LiveHost, 0, len(hosts))
	seen := map[string]struct{}{}
	for h := range results {
		if _, ok := seen[h.URL]; ok {
			continue
		}
		seen[h.URL] = struct{}{}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

func extractTitle(r io.Reader) string {
	b, err := io.ReadAll(io.LimitReader(r, 128*1024))
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	m := re.FindSubmatch(b)
	if len(m) < 2 {
		return ""
	}
	t := strings.TrimSpace(string(m[1]))
	t = strings.ReplaceAll(t, "\n", " ")
	if len(t) > 120 {
		t = t[:120]
	}
	return t
}

func scanCommonPorts(hosts []string, threads int) []model.PortHit {
	ports := []int{80, 443, 8080, 8443, 3000, 5000, 8000, 9000}
	type job struct {
		host string
		port int
	}
	jobs := make(chan job)
	results := make(chan model.PortHit, len(hosts)*len(ports))
	wg := sync.WaitGroup{}
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				addr := fmt.Sprintf("%s:%d", j.host, j.port)
				c, err := net.DialTimeout("tcp", addr, 900*time.Millisecond)
				if err == nil {
					_ = c.Close()
					results <- model.PortHit{Host: j.host, Port: j.port}
				}
			}
		}()
	}
	for _, h := range dedupe(hosts) {
		for _, p := range ports {
			jobs <- job{host: h, port: p}
		}
	}
	close(jobs)
	wg.Wait()
	close(results)

	out := make([]model.PortHit, 0)
	for hit := range results {
		out = append(out, hit)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host == out[j].Host {
			return out[i].Port < out[j].Port
		}
		return out[i].Host < out[j].Host
	})
	return out
}

func (e *Engine) discoverURLs(ctx context.Context, hosts []string, threads int) []string {
	hosts = dedupe(hosts)
	if len(hosts) == 0 {
		return nil
	}
	jobs := make(chan string)
	results := make(chan []string, len(hosts))
	wg := sync.WaitGroup{}
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				results <- e.waybackURLs(ctx, host)
			}
		}()
	}
	for _, h := range hosts {
		jobs <- h
	}
	close(jobs)
	wg.Wait()
	close(results)
	all := make([]string, 0, 1024)
	for batch := range results {
		all = append(all, batch...)
	}
	return dedupe(all)
}

func (e *Engine) waybackURLs(ctx context.Context, host string) []string {
	u := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey&limit=300", url.QueryEscape(host))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil
	}
	var raw [][]string
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	out := make([]string, 0, len(raw))
	for i, row := range raw {
		if i == 0 || len(row) == 0 {
			continue
		}
		out = append(out, row[0])
	}
	return out
}

func extractJS(urls []string) []string {
	out := make([]string, 0, len(urls)/4)
	for _, u := range urls {
		lu := strings.ToLower(u)
		if strings.Contains(lu, ".js") && !strings.Contains(lu, ".json") {
			out = append(out, u)
		}
	}
	return dedupe(out)
}

func looksLikeHost(host string) bool {
	if host == "" || strings.ContainsAny(host, " \t") {
		return false
	}
	if strings.Contains(host, "*") || strings.Contains(host, "/") {
		return false
	}
	if strings.Contains(host, "@") {
		return false
	}
	return strings.Contains(host, ".")
}

func runNuclei(ctx context.Context, hosts []model.LiveHost) ([]model.Vulnerability, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	tmp, err := os.CreateTemp("", "macaronv2_hosts_*.txt")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	for _, h := range hosts {
		if _, err := tmp.WriteString(h.URL + "\n"); err != nil {
			_ = tmp.Close()
			return nil, err
		}
	}
	_ = tmp.Close()

	cmd := exec.CommandContext(ctx, "nuclei", "-l", tmp.Name(), "-silent", "-jsonl", "-severity", "critical,high,medium", "-rate-limit", "200", "-c", "30")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(strings.NewReader(string(out)))
	vulns := make([]model.Vulnerability, 0)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var item map[string]any
		if json.Unmarshal([]byte(line), &item) != nil {
			continue
		}
		v := model.Vulnerability{}
		if tid, ok := item["template-id"].(string); ok {
			v.Template = tid
		}
		if matched, ok := item["matched-at"].(string); ok {
			v.Matched = matched
		}
		if info, ok := item["info"].(map[string]any); ok {
			if sev, ok := info["severity"].(string); ok {
				v.Severity = sev
			}
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}
