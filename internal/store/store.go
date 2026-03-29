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
}

func New(baseDir string) (*Store, error) {
	s := &Store{baseDir: baseDir}
	if err := os.MkdirAll(s.baseDir, 0o755); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) SaveScan(result model.ScanResult) error {
	targetDir := filepath.Join(s.baseDir, sanitizeFilename(result.Target))
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}

	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	scanPath := filepath.Join(targetDir, result.ID+".json")
	if err := os.WriteFile(scanPath, b, 0o644); err != nil {
		return err
	}

	latestPath := filepath.Join(targetDir, "latest.txt")
	return os.WriteFile(latestPath, []byte(result.ID), 0o644)
}

func (s *Store) GetByID(id string) (*model.ScanResult, error) {
	var found string
	errWalk := filepath.WalkDir(s.baseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(d.Name()) != ".json" {
			return nil
		}
		if strings.TrimSuffix(d.Name(), ".json") == id {
			found = path
			return errors.New("found")
		}
		return nil
	})
	if errWalk != nil && errWalk.Error() != "found" {
		return nil, errWalk
	}
	if found == "" {
		return nil, os.ErrNotExist
	}
	return readScan(found)
}

func (s *Store) LatestByTarget(target string) (*model.ScanResult, error) {
	targetDir := filepath.Join(s.baseDir, sanitizeFilename(target))
	latestPath := filepath.Join(targetDir, "latest.txt")
	b, err := os.ReadFile(latestPath)
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return nil, errors.New("empty latest scan entry")
	}
	return readScan(filepath.Join(targetDir, id+".json"))
}

func (s *Store) Summaries(limit int) ([]model.ScanSummary, error) {
	out := make([]model.ScanSummary, 0, 64)
	err := filepath.WalkDir(s.baseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() || filepath.Ext(d.Name()) != ".json" {
			return nil
		}
		r, err := readScan(path)
		if err != nil {
			return nil
		}
		out = append(out, model.ScanSummary{
			ID:         r.ID,
			Target:     r.Target,
			Mode:       r.Mode,
			FinishedAt: r.FinishedAt,
			DurationMS: r.DurationMS,
			Stats:      r.Stats,
		})
		return nil
	})
	if err != nil {
		return nil, err
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

func readScan(path string) (*model.ScanResult, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var res model.ScanResult
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func sanitizeFilename(s string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "?", "_", "*", "_", " ", "_")
	return replacer.Replace(strings.ToLower(strings.TrimSpace(s)))
}
