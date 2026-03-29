package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/root-Manas/macaron/internal/model"
)

type Store struct {
	baseDir string
	scans   string
	latest  string
}

func New(baseDir string) (*Store, error) {
	s := &Store{
		baseDir: baseDir,
		scans:   filepath.Join(baseDir, "scans"),
		latest:  filepath.Join(baseDir, "latest"),
	}
	for _, dir := range []string{s.baseDir, s.scans, s.latest} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) SaveScan(result model.ScanResult) error {
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	f := filepath.Join(s.scans, result.ID+".json")
	if err := os.WriteFile(f, b, 0o644); err != nil {
		return err
	}
	latestFile := filepath.Join(s.latest, sanitizeFilename(result.Target)+".txt")
	return os.WriteFile(latestFile, []byte(result.ID), 0o644)
}

func (s *Store) GetByID(id string) (*model.ScanResult, error) {
	f := filepath.Join(s.scans, id+".json")
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	var res model.ScanResult
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (s *Store) LatestByTarget(target string) (*model.ScanResult, error) {
	latestFile := filepath.Join(s.latest, sanitizeFilename(target)+".txt")
	b, err := os.ReadFile(latestFile)
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return nil, errors.New("empty latest scan entry")
	}
	return s.GetByID(id)
}

func (s *Store) Summaries(limit int) ([]model.ScanSummary, error) {
	entries, err := os.ReadDir(s.scans)
	if err != nil {
		return nil, err
	}
	out := make([]model.ScanSummary, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.scans, e.Name()))
		if err != nil {
			continue
		}
		var r model.ScanResult
		if err := json.Unmarshal(b, &r); err != nil {
			continue
		}
		out = append(out, model.ScanSummary{
			ID:         r.ID,
			Target:     r.Target,
			Mode:       r.Mode,
			FinishedAt: r.FinishedAt,
			DurationMS: r.DurationMS,
			Stats:      r.Stats,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].FinishedAt.After(out[j].FinishedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) Export(path string, target string) (string, error) {
	summaries, err := s.Summaries(0)
	if err != nil {
		return "", err
	}
	payload := map[string]any{
		"exported_at": time.Now().Format(time.RFC3339),
		"targets":     []model.ScanResult{},
	}
	results := make([]model.ScanResult, 0, len(summaries))
	for _, summary := range summaries {
		if target != "" && !strings.EqualFold(summary.Target, target) {
			continue
		}
		res, err := s.GetByID(summary.ID)
		if err != nil {
			continue
		}
		results = append(results, *res)
	}
	payload["targets"] = results
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	if path == "" {
		path = filepath.Join(s.baseDir, fmt.Sprintf("export_%s.json", time.Now().Format("20060102_150405")))
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func sanitizeFilename(s string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "?", "_", "*", "_", " ", "_")
	return replacer.Replace(strings.ToLower(strings.TrimSpace(s)))
}
