package ui

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/root-Manas/macaron/internal/store"
)

//go:embed assets/index.html
var assets embed.FS

type Server struct {
	Store    *store.Store
	cacheMu  sync.Mutex
	geoCache map[string]heatPoint
}

func New(st *store.Store) *Server {
	return &Server{
		Store:    st,
		geoCache: map[string]heatPoint{},
	}
}

func (s *Server) Serve(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/scans", s.handleScans)
	mux.HandleFunc("/api/results", s.handleResults)
	mux.HandleFunc("/api/heat", s.handleHeat)
	mux.HandleFunc("/api/analytics", s.handleAnalytics)
	srv := &http.Server{Addr: addr, Handler: mux}
	fmt.Printf("macaron dashboard → http://%s  (Ctrl-C to stop)\n", addr)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	}
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
			p, ok := s.lookupGeo(r.Context(), ip)
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

func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	report, err := s.Store.Analytics()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, report)
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

func (s *Server) lookupGeo(ctx context.Context, ip string) (heatPoint, bool) {
	s.cacheMu.Lock()
	if p, ok := s.geoCache[ip]; ok {
		s.cacheMu.Unlock()
		return p, true
	}
	s.cacheMu.Unlock()

	client := &http.Client{Timeout: 4 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://ip-api.com/json/"+ip+"?fields=status,country,city,lat,lon", nil)
	if err != nil {
		return heatPoint{}, false
	}
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
