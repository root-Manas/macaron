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

// DayStat holds aggregated scan findings for a single calendar day.
type DayStat struct {
	Day        string `json:"day"`
	Scans      int    `json:"scans"`
	Subdomains int    `json:"subdomains"`
	LiveHosts  int    `json:"live_hosts"`
	URLs       int    `json:"urls"`
	Vulns      int    `json:"vulns"`
}

// TargetRank holds a target ranked by vuln and live host counts.
type TargetRank struct {
	Target    string `json:"target"`
	Vulns     int    `json:"vulns"`
	LiveHosts int    `json:"live_hosts"`
}

// SeverityCount holds a vulnerability severity level and its total count.
type SeverityCount struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

// AnalyticsReport is the response returned by /api/analytics.
type AnalyticsReport struct {
	ScanCount     int             `json:"scan_count"`
	AvgDurationMS int64           `json:"avg_duration_ms"`
	Totals        ScanStats       `json:"totals"`
	Days          []DayStat       `json:"days"`
	TopTargets    []TargetRank    `json:"top_targets"`
	SeverityDist  []SeverityCount `json:"severity_dist"`
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
