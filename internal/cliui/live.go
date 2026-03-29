package cliui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/root-Manas/macaron/internal/model"
)

type LiveRenderer struct {
	out io.Writer

	mu          sync.Mutex
	color       bool
	spinnerOn   bool
	spinStop    chan struct{}
	spinFrame   int
	target      string
	stage       string
	message     string
	stageStart  time.Time
	scanStart   time.Time
	lastPrinted time.Time
}

func NewLiveRenderer(out io.Writer) *LiveRenderer {
	if out == nil {
		out = os.Stdout
	}
	useColor := strings.TrimSpace(os.Getenv("NO_COLOR")) == ""
	return &LiveRenderer{
		out:   out,
		color: useColor,
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
		r.printLinef("%s target=%s", r.info("SCAN"), r.strong(ev.Target))
		r.startSpinnerLocked()
	case model.EventStageStart:
		r.stage = ev.Stage
		r.message = ev.Message
		r.stageStart = chooseTime(ev.Timestamp, time.Now())
		r.printLinef("%s stage=%s %s", r.info("RUN"), r.stageLabel(ev.Stage), r.dim(ev.Message))
	case model.EventWarn:
		msg := ev.Message
		if strings.TrimSpace(msg) == "" {
			msg = "warning"
		}
		if ev.Stage != "" {
			r.printLinef("%s stage=%s %s", r.warn("WARN"), r.stageLabel(ev.Stage), msg)
		} else {
			r.printLinef("%s %s", r.warn("WARN"), msg)
		}
	case model.EventStageDone:
		dur := time.Duration(ev.DurationMS) * time.Millisecond
		if dur <= 0 && !r.stageStart.IsZero() {
			dur = time.Since(r.stageStart)
		}
		r.printLinef("%s stage=%s count=%d in %s", r.ok("DONE"), r.stageLabel(ev.Stage), ev.Count, dur.Round(time.Millisecond))
	case model.EventTargetDone:
		total := time.Duration(ev.DurationMS) * time.Millisecond
		if total <= 0 && !r.scanStart.IsZero() {
			total = time.Since(r.scanStart)
		}
		r.stopSpinnerLocked()
		r.printLinef("%s target=%s completed in %s", r.ok("COMPLETE"), r.strong(ev.Target), total.Round(time.Millisecond))
	}
}

func (r *LiveRenderer) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopSpinnerLocked()
}

func (r *LiveRenderer) startSpinnerLocked() {
	if r.spinnerOn {
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
	fmt.Fprint(r.out, "\r\033[2K")
}

func (r *LiveRenderer) spin() {
	frames := []string{"|", "/", "-", `\`}
	ticker := time.NewTicker(120 * time.Millisecond)
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
			line := fmt.Sprintf("%s %s %s %s %s",
				r.spinStyle(frames[r.spinFrame]),
				r.strong(r.target),
				r.dim("stage="+stage),
				msg,
				r.dim("t="+elapsed),
			)
			fmt.Fprintf(r.out, "\r\033[2K%s", line)
			r.lastPrinted = time.Now()
			r.mu.Unlock()
		case <-r.spinStop:
			return
		}
	}
}

func (r *LiveRenderer) printLinef(format string, args ...any) {
	// Avoid overwriting a spinner frame line.
	fmt.Fprint(r.out, "\r\033[2K")
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
	stage = strings.TrimSpace(strings.ToLower(stage))
	if stage == "" {
		return "unknown"
	}
	return stage
}

func chooseTime(v time.Time, fallback time.Time) time.Time {
	if v.IsZero() {
		return fallback
	}
	return v
}
