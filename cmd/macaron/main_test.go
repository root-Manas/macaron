package main

import (
	"os"
	"testing"
)

func withArgs(args []string, fn func()) {
	orig := osArgs()
	setOsArgs(args)
	defer setOsArgs(orig)
	fn()
}

func TestNormalizeLegacySetup(t *testing.T) {
	withArgs([]string{"macaron", "-setup"}, func() {
		normalizeLegacyArgs()
		if osArgs()[1] != "--setup" {
			t.Fatalf("expected --setup, got %s", osArgs()[1])
		}
	})
}

func TestNormalizeCommandScan(t *testing.T) {
	withArgs([]string{"macaron", "scan", "example.com", "--fast"}, func() {
		normalizeCommandArgs()
		args := osArgs()
		want := []string{"macaron", "--scan", "example.com", "--fast"}
		if len(args) != len(want) {
			t.Fatalf("unexpected len: %#v", args)
		}
		for i := range want {
			if args[i] != want[i] {
				t.Fatalf("idx %d: got %q want %q", i, args[i], want[i])
			}
		}
	})
}

func TestApplyProfilePassive(t *testing.T) {
	mode := "wide"
	rate := 150
	threads := 30
	stages := "all"
	applyProfile("passive", &mode, &rate, &threads, &stages)
	if mode != "osint" || rate != 40 || threads != 10 || stages != "subdomains,http,urls" {
		t.Fatalf("unexpected passive values: mode=%s rate=%d threads=%d stages=%s", mode, rate, threads, stages)
	}
}

func TestApplyProfileAggressive(t *testing.T) {
	mode := "wide"
	rate := 150
	threads := 30
	stages := "all"
	applyProfile("aggressive", &mode, &rate, &threads, &stages)
	if rate != 350 || threads != 70 || stages != "all" {
		t.Fatalf("unexpected aggressive values: rate=%d threads=%d stages=%s", rate, threads, stages)
	}
}

func osArgs() []string {
	return append([]string(nil), os.Args...)
}

func setOsArgs(v []string) {
	os.Args = append([]string(nil), v...)
}
