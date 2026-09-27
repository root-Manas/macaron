package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/root-Manas/macaron/internal/model"
)

func TestSaveScanRepairsMirrorAfterRestart(t *testing.T) {
	dir := t.TempDir()
	result := model.ScanResult{
		ID:         "scan-1",
		Target:     "example.com",
		Mode:       model.ModeWide,
		Subdomains: []string{"example.com"},
	}

	st, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveScan(result); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	mirror := filepath.Join(dir, "example.com", "scan-1.json")
	if err := os.Remove(mirror); err != nil {
		t.Fatal(err)
	}

	st, err = New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, err := os.Stat(mirror); err != nil {
		t.Fatalf("expected mirror to be repaired: %v", err)
	}
	got, err := st.GetByID(result.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Target != result.Target {
		t.Fatalf("expected target %q, got %q", result.Target, got.Target)
	}
}
