package cliui

import (
	"fmt"
	"os"
	"strings"
)

// ANSI color codes.
const (
	cReset   = "\033[0m"
	cBold    = "\033[1m"
	cDim     = "\033[2m"
	cCyan    = "\033[36m"
	cGreen   = "\033[32m"
	cYellow  = "\033[33m"
	cRed     = "\033[31m"
	cMagenta = "\033[35m"
)

// colorEnabled returns true unless NO_COLOR is set (https://no-color.org).
func colorEnabled() bool {
	return strings.TrimSpace(os.Getenv("NO_COLOR")) == ""
}

func cp(codes, v string) string {
	if !colorEnabled() {
		return v
	}
	return codes + v + cReset
}

// Info writes a cyan [INF] prefixed line to stderr.
func Info(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	prefix := cp(cCyan+cBold, "[INF]")
	fmt.Fprintf(os.Stderr, "%s %s\n", prefix, msg)
}

// Warn writes a yellow [WRN] prefixed line to stderr.
func Warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	prefix := cp(cYellow+cBold, "[WRN]")
	fmt.Fprintf(os.Stderr, "%s %s\n", prefix, msg)
}

// Err writes a red [ERR] prefixed line to stderr.
func Err(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	prefix := cp(cRed+cBold, "[ERR]")
	fmt.Fprintf(os.Stderr, "%s %s\n", prefix, msg)
}

// OK writes a green [OK] prefixed line to stderr.
func OK(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	prefix := cp(cGreen+cBold, "[OK]")
	fmt.Fprintf(os.Stderr, "%s %s\n", prefix, msg)
}

// PrintBanner writes the macaron startup banner to stderr.
// It respects NO_COLOR and is silent when quiet is true.
func PrintBanner(version string, quiet bool) {
	if quiet {
		return
	}
	c := colorEnabled()

	teal := func(s string) string {
		if !c {
			return s
		}
		return cCyan + cBold + s + cReset
	}
	dim := func(s string) string {
		if !c {
			return s
		}
		return cDim + s + cReset
	}
	magenta := func(s string) string {
		if !c {
			return s
		}
		return cMagenta + cBold + s + cReset
	}

	// Box-drawing ASCII art for "MACARON" — safe in Go raw string literals.
	art := []string{
		`╔╦╗╔═╗╔═╗╔═╗╦═╗╔═╗╔╗╔`,
		`║║║╠═╣║  ╠═╣╠╦╝║ ║║║║`,
		`╩ ╩╩ ╩╚═╝╩ ╩╩╚═╚═╝╝╚╝`,
	}

	fmt.Fprintln(os.Stderr)
	for _, line := range art {
		fmt.Fprintf(os.Stderr, "  %s\n", teal(line))
	}
	fmt.Fprintf(os.Stderr, "\n  %s  %s\n", magenta("Fast Recon Workflow"), dim("v"+version))
	fmt.Fprintf(os.Stderr, "  %s\n", dim("github.com/root-Manas/macaron"))
	fmt.Fprintf(os.Stderr, "  %s\n\n", dim(strings.Repeat("─", 40)))
}

// Highlight wraps v in bold white.
func Highlight(v string) string {
	return cp(cBold, v)
}

// Muted wraps v in dim white.
func Muted(v string) string {
	return cp(cDim, v)
}

// GreenText wraps v in green.
func GreenText(v string) string {
	return cp(cGreen, v)
}

// RedText wraps v in red.
func RedText(v string) string {
	return cp(cRed, v)
}

// YellowText wraps v in yellow.
func YellowText(v string) string {
	return cp(cYellow, v)
}

// CyanText wraps v in cyan.
func CyanText(v string) string {
	return cp(cCyan, v)
}
