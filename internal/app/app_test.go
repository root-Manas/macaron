package app

import (
	"os"
	"path/filepath"
	"testing"
)

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
