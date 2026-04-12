package main

import (
	"testing"
)

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

func TestApplyProfileBalanced(t *testing.T) {
	mode := "wide"
	rate := 150
	threads := 30
	stages := "all"
	applyProfile("balanced", &mode, &rate, &threads, &stages)
	// balanced leaves defaults unchanged
	if mode != "wide" || rate != 150 || threads != 30 || stages != "all" {
		t.Fatalf("unexpected balanced values: mode=%s rate=%d threads=%d stages=%s", mode, rate, threads, stages)
	}
}

func TestLooksLikeDomain(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"Example.COM", true},  // uppercase TLD accepted
		{"-flag", false},
		{"nodots", false},
		{"has space.com", false},
		{"example.123", false}, // numeric tld
		{"example.", false},    // empty tld
		{"example.c", false},   // tld too short
	}
	for _, c := range cases {
		got := looksLikeDomain(c.in)
		if got != c.want {
			t.Errorf("looksLikeDomain(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestMacaronHomeOverride(t *testing.T) {
	got, err := macaronHome("/tmp/test-storage")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/test-storage" {
		t.Fatalf("expected /tmp/test-storage, got %s", got)
	}
}
