package cliui

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const art = `
 ___ ___  _   ___   _   ___  ___  _  _
|  \/  | /_\ / __| /_\ | _ \/ _ \| \| |
| |\/| |/ _ \ (__ / _ \|   / (_) | .` + "`" + ` |
|_|  |_/_/ \_\___/_/ \_\_|_\\___/|_|\_|`

// PrintBanner writes the macaron banner to w. If quiet is true, nothing is written.
func PrintBanner(w io.Writer, version string, quiet bool) {
	if quiet {
		return
	}
	if w == nil {
		w = os.Stderr
	}
	noColor := strings.TrimSpace(os.Getenv("NO_COLOR")) != ""
	if noColor {
		fmt.Fprintf(w, "%s\n  offensive recon framework  %s\n\n", art, version)
		return
	}
	fmt.Fprintf(w, "\033[1;35m%s\033[0m\n  \033[2;37moffensive recon framework\033[0m  \033[1;37m%s\033[0m\n\n", art, version)
}

// Info prints a cyan [INFO] prefixed line.
func Info(format string, a ...any) {
	printPrefixed("36", "INFO", format, a...)
}

// OK prints a green [OK] prefixed line.
func OK(format string, a ...any) {
	printPrefixed("32", "OK", format, a...)
}

// Warn prints a yellow [WARN] prefixed line.
func Warn(format string, a ...any) {
	printPrefixed("33", "WARN", format, a...)
}

// Err prints a red [ERR] prefixed line to stderr.
func Err(format string, a ...any) {
	noColor := strings.TrimSpace(os.Getenv("NO_COLOR")) != ""
	label := "[ERR]"
	if !noColor {
		label = "\033[31m[ERR]\033[0m"
	}
	fmt.Fprintf(os.Stderr, label+" "+format+"\n", a...)
}

func printPrefixed(code, tag, format string, a ...any) {
	noColor := strings.TrimSpace(os.Getenv("NO_COLOR")) != ""
	label := "[" + tag + "]"
	if !noColor {
		label = "\033[" + code + "m[" + tag + "]\033[0m"
	}
	fmt.Printf(label+" "+format+"\n", a...)
}
