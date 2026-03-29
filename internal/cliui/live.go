package cliui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/root-Manas/macaron/internal/model"
)

var stageOrder = []string{"subdomains", "http", "ports", "urls", "vulns"}

type LiveRenderer struct {
	out io.Writer

	mu            sync.Mutex
	color         bool
	isTTY         bool
	spinnerOn     bool
	spinStop      chan struct{}
	spinFrame     int
	target        string
	stage         string
	message       string
	stageStart    time.Time
	scanStart     time.Time
	totalStages   int
	stageComplete map[string]bool
	doneCount     int
}

func NewLiveRenderer(out io.Writer, enabledStages map[string]bool) *LiveRenderer {
	if out == nil {
		out = os.Stdout
	}
	f, ok := out.(*os.File)
	isTTY := ok && (isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd()))
	useColor := strings.TrimSpace(os.Getenv("NO_COLOR")) == "" && isTTY
	return &LiveRenderer{
		out:           out,
		color:         useColor,
		isTTY:         isTTY,
		totalStages:   countEnabledStages(enabledStages),
		stageComplete: map[string]bool{},
	}
}

func (r *LiveRenderer) Handle(ev model.StageEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch ev.Type {
	case model.EventTargetStart:
		r.target = ev.Target
		r.scanStart = chooseTime(ev.Timestamp, time.Now())
		r.stage = ""
		r.message = "initializing workflow"
		r.stageStart = time.Now()
		r.doneCount = 0
		r.stageComplete = map[string]bool{}
		r.printBannerLocked()
		r.printLinef("%s target=%s profile=active", r.info("SCAN"), r.strong(ev.Target))
		r.startSpinnerLocked()
	case model.EventStageStart:
		r.stage = normalizeStage(ev.Stage)
		r.message = ev.Message
		r.stageStart = chooseTime(ev.Timestamp, time.Now())
		r.printLinef("%s [%d/%d] stage=%s %s", r.info("RUN"), r.doneCount+1, r.totalStages, r.stageLabel(r.stage), r.dim(ev.Message))
	case model.EventWarn:
		msg := ev.Message
		if strings.TrimSpace(msg) == "" {
			msg = "warning"
		}
		if ev.Stage != "" {
			r.printLinef("%s stage=%s %s", r.warn("WARN"), r.stageLabel(normalizeStage(ev.Stage)), msg)
		} else {
			r.printLinef("%s %s", r.warn("WARN"), msg)
		}
	case model.EventStageDone:
		stage := normalizeStage(ev.Stage)
		if !r.stageComplete[stage] {
			r.stageComplete[stage] = true
			r.doneCount++
		}
		dur := time.Duration(ev.DurationMS) * time.Millisecond
		if dur <= 0 && !r.stageStart.IsZero() {
			dur = time.Since(r.stageStart)
		}
		bar := r.progressBarLocked(26)
		r.printLinef("%s %s %d/%d stage=%s count=%d in %s", r.ok("DONE"), bar, r.doneCount, r.totalStages, r.stageLabel(stage), ev.Count, dur.Round(time.Millisecond))
	case model.EventTargetDone:
		total := time.Duration(ev.DurationMS) * time.Millisecond
		if total <= 0 && !r.scanStart.IsZero() {
			total = time.Since(r.scanStart)
		}
		r.stopSpinnerLocked()
		r.printLinef("%s %s completed in %s", r.ok("COMPLETE"), r.strong(ev.Target), total.Round(time.Millisecond))
		r.printLinef("%s %s", r.info("PIPE"), r.progressBarLocked(26))
	}
}

func (r *LiveRenderer) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopSpinnerLocked()
}

func (r *LiveRenderer) startSpinnerLocked() {
	if !r.isTTY || r.spinnerOn {
		return
	}
	r.spinnerOn = true
	r.spinStop = make(chan struct{})
	go r.spin()
}

func (r *LiveRenderer) stopSpinnerLocked() {
	if !r.spinnerOn {
		return
	}
	close(r.spinStop)
	r.spinnerOn = false
	if r.isTTY {
		fmt.Fprint(r.out, "\r\033[2K")
	}
}

func (r *LiveRenderer) spin() {
	frames := []string{"|", "/", "-", `\\`}
	ticker := time.NewTicker(180 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.mu.Lock()
			r.spinFrame = (r.spinFrame + 1) % len(frames)
			stage := r.stage
			if strings.TrimSpace(stage) == "" {
				stage = "bootstrap"
			}
			msg := strings.TrimSpace(r.message)
			if msg == "" {
				msg = "working"
			}
			elapsed := "--"
			if !r.stageStart.IsZero() {
				elapsed = time.Since(r.stageStart).Round(time.Second).String()
			}
			bar := r.progressBarLocked(18)
			line := fmt.Sprintf("%s %s %s stage=%s %s %s", r.spinStyle(frames[r.spinFrame]), r.strong(r.target), bar, r.stageLabel(stage), msg, r.dim("t="+elapsed))
			fmt.Fprintf(r.out, "\r\033[2K%s", line)
			r.mu.Unlock()
		case <-r.spinStop:
			return
		}
	}
}

func (r *LiveRenderer) progressBarLocked(width int) string {
	if width < 4 {
		width = 4
	}
	total := r.totalStages
	if total <= 0 {
		total = 1
	}
	done := r.doneCount
	if done > total {
		done = total
	}
	filled := int(float64(done) / float64(total) * float64(width))
	if done > 0 && filled == 0 {
		filled = 1
	}
	if done == total {
		filled = width
	}
	return "[" + strings.Repeat("#", filled) + strings.Repeat("-", width-filled) + "]"
}

func (r *LiveRenderer) printBannerLocked() {
	line := strings.Repeat("=", 72)
	r.printLinef("%s", r.dim(line))
	r.printLinef("%s %s", r.strong("macaronV2"), r.info("LIVE SCAN CONSOLE"))
	r.printLinef("%s", r.dim(line))
}

func (r *LiveRenderer) printLinef(format string, args ...any) {
	if r.isTTY {
		fmt.Fprint(r.out, "\r\033[2K")
	}
	fmt.Fprintf(r.out, format+"\n", args...)
}

func (r *LiveRenderer) strong(v string) string {
	if !r.color {
		return v
	}
	return "\033[1;37m" + v + "\033[0m"
}

func (r *LiveRenderer) dim(v string) string {
	if !r.color {
		return v
	}
	return "\033[2;37m" + v + "\033[0m"
}

func (r *LiveRenderer) info(v string) string {
	return r.paint(v, "36")
}

func (r *LiveRenderer) ok(v string) string {
	return r.paint(v, "32")
}

func (r *LiveRenderer) warn(v string) string {
	return r.paint(v, "33")
}

func (r *LiveRenderer) spinStyle(v string) string {
	return r.paint(v, "35")
}

func (r *LiveRenderer) paint(v, code string) string {
	if !r.color {
		return "[" + v + "]"
	}
	return "\033[" + code + "m[" + v + "]\033[0m"
}

func (r *LiveRenderer) stageLabel(stage string) string {
	stage = normalizeStage(stage)
	if stage == "" {
		return "unknown"
	}
	return stage
}

func countEnabledStages(enabled map[string]bool) int {
	if len(enabled) == 0 {
		return len(stageOrder)
	}
	total := 0
	for _, st := range stageOrder {
		if enabled[st] {
			total++
		}
	}
	if total == 0 {
		return len(stageOrder)
	}
	return total
}

func normalizeStage(stage string) string {
	return strings.ToLower(strings.TrimSpace(stage))
}

func chooseTime(v time.Time, fallback time.Time) time.Time {
	if v.IsZero() {
		return fallback
	}
	return v
}
