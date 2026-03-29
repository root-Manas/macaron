package ui

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/root-Manas/macaron/internal/app"
	"github.com/root-Manas/macaron/internal/model"
	"github.com/root-Manas/macaron/internal/store"
)

//go:embed assets/index.html
var assets embed.FS

type Server struct {
	Store   *store.Store
	App     *app.App
	APIKeys map[string]string

	cacheMu  sync.Mutex
	geoCache map[string]heatPoint

	liveMu sync.Mutex
	live   map[string]*liveScan
}

type liveScan struct {
	JobID      string            `json:"job_id"`
	Target     string            `json:"target"`
	Mode       string            `json:"mode"`
	Stages     string            `json:"stages"`
	Rate       int               `json:"rate"`
	Threads    int               `json:"threads"`
	Status     string            `json:"status"`
	Error      string            `json:"error,omitempty"`
	StartedAt  time.Time         `json:"started_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	FinishedAt *time.Time        `json:"finished_at,omitempty"`
	Result     *model.ScanResult `json:"result,omitempty"`
	Log        []string          `json:"log"`
}

func New(ap *app.App, apiKeys map[string]string) *Server {
	keys := map[string]string{}
	for k, v := range apiKeys {
		keys[k] = v
	}
	return &Server{
		Store:    ap.Store,
		App:      ap,
		APIKeys:  keys,
		geoCache: map[string]heatPoint{},
		live:     map[string]*liveScan{},
	}
}

func (s *Server) Serve(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/scans", s.handleScans)
	mux.HandleFunc("/api/results", s.handleResults)
	mux.HandleFunc("/api/heat", s.handleHeat)
	mux.HandleFunc("/api/live", s.handleLive)
	mux.HandleFunc("/api/scan/start", s.handleStartScan)
	fmt.Printf("macaronV2 dashboard on http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.Summaries(200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, items)
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if id == "" && target == "" {
		http.Error(w, "id or target is required", http.StatusBadRequest)
		return
	}
	var (
		data any
		err  error
	)
	if id != "" {
		data, err = s.Store.GetByID(id)
	} else {
		data, err = s.Store.LatestByTarget(target)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, data)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	b, err := assets.ReadFile("assets/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	if id != "" {
		job, ok := s.live[id]
		if !ok {
			http.Error(w, "live job not found", http.StatusNotFound)
			return
		}
		writeJSON(w, cloneLive(job))
		return
	}
	items := make([]liveScan, 0, len(s.live))
	for _, v := range s.live {
		items = append(items, cloneLive(v))
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].StartedAt.After(items[j].StartedAt)
	})
	writeJSON(w, items)
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Target  string `json:"target"`
		Mode    string `json:"mode"`
		Stages  string `json:"stages"`
		Rate    int    `json:"rate"`
		Threads int    `json:"threads"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json payload", http.StatusBadRequest)
		return
	}
	targets, err := app.ParseTargets([]string{req.Target}, "", false)
	if err != nil || len(targets) == 0 {
		http.Error(w, "valid target is required", http.StatusBadRequest)
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "wide"
	}
	if req.Stages == "" {
		req.Stages = "all"
	}
	if req.Rate <= 0 {
		req.Rate = 150
	}
	if req.Threads <= 0 {
		req.Threads = 30
	}

	jobID := fmt.Sprintf("live-%d", time.Now().UnixNano())
	now := time.Now()
	job := &liveScan{
		JobID:     jobID,
		Target:    targets[0],
		Mode:      mode,
		Stages:    req.Stages,
		Rate:      req.Rate,
		Threads:   req.Threads,
		Status:    "queued",
		StartedAt: now,
		UpdatedAt: now,
		Log:       []string{fmt.Sprintf("[%s] scan queued for %s", now.Format("15:04:05"), targets[0])},
	}
	s.liveMu.Lock()
	s.live[jobID] = job
	s.liveMu.Unlock()
	go s.runScan(jobID)
	writeJSON(w, map[string]string{"job_id": jobID})
}

func (s *Server) runScan(jobID string) {
	s.updateLive(jobID, func(j *liveScan) {
		j.Status = "running"
		n := time.Now()
		j.UpdatedAt = n
		j.Log = append(j.Log, fmt.Sprintf("[%s] scan started", n.Format("15:04:05")))
	})

	job := s.getLive(jobID)
	if job == nil {
		return
	}
	results, err := s.App.Scan(context.Background(), app.ScanArgs{
		Targets:       []string{job.Target},
		Mode:          model.Mode(job.Mode),
		Rate:          job.Rate,
		Threads:       job.Threads,
		EnabledStages: app.ParseStages(job.Stages),
		APIKeys:       s.APIKeys,
		Progress: func(ev model.StageEvent) {
			s.logEvent(jobID, ev)
		},
	})
	if err != nil {
		s.updateLive(jobID, func(j *liveScan) {
			n := time.Now()
			j.Status = "failed"
			j.Error = err.Error()
			j.UpdatedAt = n
			j.FinishedAt = &n
			j.Log = append(j.Log, fmt.Sprintf("[%s] scan failed: %s", n.Format("15:04:05"), err.Error()))
		})
		return
	}
	s.updateLive(jobID, func(j *liveScan) {
		n := time.Now()
		j.Status = "done"
		j.UpdatedAt = n
		j.FinishedAt = &n
		if len(results) > 0 {
			j.Result = &results[0]
		}
		j.Log = append(j.Log, fmt.Sprintf("[%s] scan completed", n.Format("15:04:05")))
	})
}

func (s *Server) logEvent(jobID string, ev model.StageEvent) {
	line := formatEventLine(ev)
	s.updateLive(jobID, func(j *liveScan) {
		j.UpdatedAt = time.Now()
		if line != "" {
			j.Log = append(j.Log, line)
			if len(j.Log) > 500 {
				j.Log = j.Log[len(j.Log)-500:]
			}
		}
	})
}

func formatEventLine(ev model.StageEvent) string {
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	prefix := fmt.Sprintf("[%s]", ts.Format("15:04:05"))
	switch ev.Type {
	case model.EventTargetStart:
		return fmt.Sprintf("%s target=%s started", prefix, ev.Target)
	case model.EventStageStart:
		return fmt.Sprintf("%s stage=%s started %s", prefix, ev.Stage, strings.TrimSpace(ev.Message))
	case model.EventStageDone:
		return fmt.Sprintf("%s stage=%s done count=%d duration=%dms", prefix, ev.Stage, ev.Count, ev.DurationMS)
	case model.EventWarn:
		return fmt.Sprintf("%s warning stage=%s %s", prefix, ev.Stage, strings.TrimSpace(ev.Message))
	case model.EventTargetDone:
		return fmt.Sprintf("%s target=%s completed duration=%dms", prefix, ev.Target, ev.DurationMS)
	default:
		return ""
	}
}

func (s *Server) getLive(jobID string) *liveScan {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	v, ok := s.live[jobID]
	if !ok {
		return nil
	}
	cp := cloneLive(v)
	return &cp
}

func (s *Server) updateLive(jobID string, fn func(*liveScan)) {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	v, ok := s.live[jobID]
	if !ok {
		return
	}
	fn(v)
}

func cloneLive(in *liveScan) liveScan {
	if in == nil {
		return liveScan{}
	}
	out := *in
	out.Log = append([]string(nil), in.Log...)
	return out
}

type heatPoint struct {
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Count   int     `json:"count"`
	Country string  `json:"country"`
	City    string  `json:"city"`
}

func (s *Server) handleHeat(w http.ResponseWriter, r *http.Request) {
	summaries, err := s.Store.Summaries(200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	acc := map[string]heatPoint{}
	for _, sm := range summaries {
		scan, err := s.Store.GetByID(sm.ID)
		if err != nil {
			continue
		}
		for _, live := range scan.LiveHosts {
			host := hostFromURL(live.URL)
			if host == "" {
				continue
			}
			ip := firstResolvableIP(host)
			if ip == "" {
				continue
			}
			p, ok := s.lookupGeo(ip)
			if !ok {
				continue
			}
			key := fmt.Sprintf("%.2f,%.2f", p.Lat, p.Lon)
			cur := acc[key]
			cur.Lat = p.Lat
			cur.Lon = p.Lon
			cur.Country = p.Country
			cur.City = p.City
			cur.Count++
			acc[key] = cur
		}
	}
	out := make([]heatPoint, 0, len(acc))
	for _, p := range acc {
		out = append(out, p)
	}
	writeJSON(w, out)
}

func hostFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func firstResolvableIP(host string) string {
	ips, err := net.LookupIP(host)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		if v4.IsPrivate() || v4.IsLoopback() || v4.IsUnspecified() {
			continue
		}
		return v4.String()
	}
	return ""
}

func (s *Server) lookupGeo(ip string) (heatPoint, bool) {
	s.cacheMu.Lock()
	if p, ok := s.geoCache[ip]; ok {
		s.cacheMu.Unlock()
		return p, true
	}
	s.cacheMu.Unlock()

	client := &http.Client{Timeout: 4 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, "http://ip-api.com/json/"+ip+"?fields=status,country,city,lat,lon", nil)
	resp, err := client.Do(req)
	if err != nil {
		return heatPoint{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return heatPoint{}, false
	}
	var payload struct {
		Status  string  `json:"status"`
		Country string  `json:"country"`
		City    string  `json:"city"`
		Lat     float64 `json:"lat"`
		Lon     float64 `json:"lon"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return heatPoint{}, false
	}
	if payload.Status != "success" {
		return heatPoint{}, false
	}
	point := heatPoint{
		Lat:     payload.Lat,
		Lon:     payload.Lon,
		Country: payload.Country,
		City:    payload.City,
		Count:   1,
	}
	s.cacheMu.Lock()
	s.geoCache[ip] = point
	s.cacheMu.Unlock()
	return point, true
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(data)
}
