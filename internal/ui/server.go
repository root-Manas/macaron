package ui

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/root-Manas/macaron/internal/store"
)

//go:embed assets/index.html
var assets embed.FS

type Server struct {
	Store *store.Store
}

func New(st *store.Store) *Server {
	return &Server{Store: st}
}

func (s *Server) Serve(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/scans", s.handleScans)
	mux.HandleFunc("/api/results", s.handleResults)
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

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(data)
}
