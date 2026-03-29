package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/root-Manas/macaron/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct {
	baseDir string
	db      *sql.DB
}

func New(baseDir string) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(baseDir, "macaron.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=DELETE; PRAGMA synchronous=NORMAL;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &Store{baseDir: baseDir, db: db}
	if err := s.initSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) initSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  mode TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  stats_json TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_target_finished ON scans(target, finished_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_finished ON scans(finished_at DESC);
`)
	return err
}

func (s *Store) SaveScan(result model.ScanResult) error {
	statsJSON, err := json.Marshal(result.Stats)
	if err != nil {
		return err
	}
	payloadJSON, err := json.Marshal(result)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`
INSERT INTO scans(id,target,mode,started_at,finished_at,duration_ms,stats_json,payload_json)
VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
  target=excluded.target,
  mode=excluded.mode,
  started_at=excluded.started_at,
  finished_at=excluded.finished_at,
  duration_ms=excluded.duration_ms,
  stats_json=excluded.stats_json,
  payload_json=excluded.payload_json
`,
		result.ID,
		result.Target,
		string(result.Mode),
		result.StartedAt.Format(time.RFC3339Nano),
		result.FinishedAt.Format(time.RFC3339Nano),
		result.DurationMS,
		string(statsJSON),
		string(payloadJSON),
	)
	if err != nil {
		return err
	}

	// Keep a per-target folder mirror for easy file browsing.
	targetDir := filepath.Join(s.baseDir, sanitizeFilename(result.Target))
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}
	pretty, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(filepath.Join(targetDir, result.ID+".json"), pretty, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(targetDir, "latest.txt"), []byte(result.ID), 0o644)
}

func (s *Store) GetByID(id string) (*model.ScanResult, error) {
	row := s.db.QueryRow(`SELECT payload_json FROM scans WHERE id = ? LIMIT 1`, id)
	var payload string
	if err := row.Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	return decodeScan(payload)
}

func (s *Store) LatestByTarget(target string) (*model.ScanResult, error) {
	row := s.db.QueryRow(`SELECT payload_json FROM scans WHERE lower(target)=lower(?) ORDER BY finished_at DESC LIMIT 1`, target)
	var payload string
	if err := row.Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	return decodeScan(payload)
}

func (s *Store) Summaries(limit int) ([]model.ScanSummary, error) {
	query := `SELECT id,target,mode,finished_at,duration_ms,stats_json FROM scans ORDER BY finished_at DESC`
	args := []any{}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.ScanSummary, 0, 128)
	for rows.Next() {
		var (
			id, target, modeStr, finishedAtRaw, statsRaw string
			durationMS                                   int64
		)
		if err := rows.Scan(&id, &target, &modeStr, &finishedAtRaw, &durationMS, &statsRaw); err != nil {
			continue
		}
		var stats model.ScanStats
		_ = json.Unmarshal([]byte(statsRaw), &stats)
		finishedAt, _ := time.Parse(time.RFC3339Nano, finishedAtRaw)
		out = append(out, model.ScanSummary{
			ID:         id,
			Target:     target,
			Mode:       model.Mode(modeStr),
			FinishedAt: finishedAt,
			DurationMS: durationMS,
			Stats:      stats,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].FinishedAt.After(out[j].FinishedAt)
	})
	return out, nil
}

func (s *Store) Export(path string, target string) (string, error) {
	query := `SELECT payload_json FROM scans`
	args := []any{}
	if strings.TrimSpace(target) != "" {
		query += ` WHERE lower(target)=lower(?)`
		args = append(args, target)
	}
	query += ` ORDER BY finished_at DESC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	results := make([]model.ScanResult, 0, 64)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			continue
		}
		res, err := decodeScan(payload)
		if err != nil {
			continue
		}
		results = append(results, *res)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	payload := map[string]any{
		"exported_at": time.Now().Format(time.RFC3339),
		"targets":     results,
	}
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

func decodeScan(payload string) (*model.ScanResult, error) {
	var res model.ScanResult
	if err := json.Unmarshal([]byte(payload), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func sanitizeFilename(s string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "?", "_", "*", "_", " ", "_")
	return replacer.Replace(strings.ToLower(strings.TrimSpace(s)))
}
