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
	if mode != "wide" || rate != 40 || threads != 10 || stages != "subdomains,http,urls" {
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
		{"Example.COM", true}, // uppercase TLD accepted
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

	got, err = macaronHome("~/test-storage")
	if err != nil {
		t.Fatal(err)
	}
	if got != "~/test-storage" {
		t.Fatalf("expected ~/test-storage to remain literal, got %s", got)
	}

	override := " /tmp/test-storage "
	got, err = macaronHome(override)
	if err != nil {
		t.Fatal(err)
	}
	if got != override {
		t.Fatalf("expected %q to remain unchanged, got %q", override, got)
	}
}

func TestMacaronHomeEnvironmentOverride(t *testing.T) {
	for _, want := range []string{"/tmp/macaron-home ", "~/macaron-home"} {
		t.Run(want, func(t *testing.T) {
			t.Setenv("MACARON_HOME", want)

			got, err := macaronHome("")
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("expected %q, got %q", want, got)
			}
		})
	}
}
