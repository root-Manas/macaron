package model

import "time"

type Mode string

const (
	ModeWide   Mode = "wide"
	ModeNarrow Mode = "narrow"
	ModeFast   Mode = "fast"
	ModeDeep   Mode = "deep"
	ModeOSINT  Mode = "osint"
)

type LiveHost struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Title      string `json:"title,omitempty"`
	Tech       string `json:"tech,omitempty"`
}

type PortHit struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type Vulnerability struct {
	Template string `json:"template"`
	Severity string `json:"severity"`
	Matched  string `json:"matched"`
}

type ScanStats struct {
	Subdomains int `json:"subdomains"`
	LiveHosts  int `json:"live_hosts"`
	Ports      int `json:"ports"`
	URLs       int `json:"urls"`
	JSFiles    int `json:"js_files"`
	Vulns      int `json:"vulns"`
}

type ScanResult struct {
	ID         string          `json:"id"`
	Target     string          `json:"target"`
	Mode       Mode            `json:"mode"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	DurationMS int64           `json:"duration_ms"`
	Stats      ScanStats       `json:"stats"`
	Subdomains []string        `json:"subdomains"`
	LiveHosts  []LiveHost      `json:"live_hosts"`
	Ports      []PortHit       `json:"ports"`
	URLs       []string        `json:"urls"`
	JSFiles    []string        `json:"js_files"`
	Vulns      []Vulnerability `json:"vulns"`
	Warnings   []string        `json:"warnings,omitempty"`
}

type ScanSummary struct {
	ID         string    `json:"id"`
	Target     string    `json:"target"`
	Mode       Mode      `json:"mode"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMS int64     `json:"duration_ms"`
	Stats      ScanStats `json:"stats"`
}

type ToolStatus struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
}

type StageEventType string

const (
	EventTargetStart StageEventType = "target_start"
	EventTargetDone  StageEventType = "target_done"
	EventStageStart  StageEventType = "stage_start"
	EventStageDone   StageEventType = "stage_done"
	EventWarn        StageEventType = "warn"
)

type StageEvent struct {
	Timestamp  time.Time      `json:"timestamp"`
	Type       StageEventType `json:"type"`
	Target     string         `json:"target"`
	Stage      string         `json:"stage,omitempty"`
	Message    string         `json:"message,omitempty"`
	Count      int            `json:"count,omitempty"`
	DurationMS int64          `json:"duration_ms,omitempty"`
}
