package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/root-Manas/macaron/internal/model"
)

func TestShowResultsJSONIsMachineReadable(t *testing.T) {
	storage := filepath.Join(t.TempDir(), "storage")
	application, err := New(storage)
	if err != nil {
		t.Fatal(err)
	}
	defer application.Store.Close()

	want := model.ScanResult{ID: "scan-json", Target: "example.com", Mode: model.ModeWide}
	if err := application.Store.SaveScan(want); err != nil {
		t.Fatal(err)
	}
	raw, err := application.ShowResultsJSON("", want.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got model.ScanResult
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("expected valid JSON, got %q: %v", raw, err)
	}
	if got.ID != want.ID {
		t.Fatalf("expected scan %q, got %q", want.ID, got.ID)
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"https://Example.com/login":  "example.com",
		"http://api.test.io:8443/v1": "api.test.io",
		"plain.org":                  "plain.org",
	}
	for in, want := range cases {
		if got := normalizeTarget(in); got != want {
			t.Fatalf("normalizeTarget(%q)=%q want=%q", in, got, want)
		}
	}
}

func TestParseTargets(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "targets.txt")
	if err := os.WriteFile(f, []byte("example.com\nhttps://example.com\napi.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := ParseTargets([]string{"test.com"}, f, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 unique targets, got %d: %#v", len(out), out)
	}
}

func TestParseStages(t *testing.T) {
	all := ParseStages("all")
	if !all["subdomains"] || !all["http"] || !all["ports"] || !all["urls"] || !all["vulns"] {
		t.Fatalf("expected all stages enabled, got %#v", all)
	}
	custom := ParseStages("subdomains,http")
	if !custom["subdomains"] || !custom["http"] || custom["vulns"] {
		t.Fatalf("unexpected stage parsing result: %#v", custom)
	}
}
