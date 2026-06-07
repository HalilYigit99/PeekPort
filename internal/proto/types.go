package proto

import "time"

type ScanMode string
type Protocol string
type PortState string

const (
	ModeFast ScanMode = "fast"
	ModeFull ScanMode = "full"

	TCP Protocol = "tcp"
	UDP Protocol = "udp"

	Open     PortState = "open"
	Closed   PortState = "closed"
	Filtered PortState = "filtered"
)

type ScanRequest struct {
	Target      string     `json:"target"`
	Mode        ScanMode   `json:"mode"`
	Protocols   []Protocol `json:"protocols"`
	TimeoutMS   int        `json:"timeout_ms"`
	Concurrency int        `json:"concurrency"`
}

type Vulnerability struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Severity string  `json:"severity"` // Critical | High | Medium | Low | Info
	CVE      string  `json:"cve,omitempty"`
	CVSS     float64 `json:"cvss,omitempty"`
	Desc     string  `json:"description"`
}

type PortResult struct {
	Port     int             `json:"port"`
	Protocol Protocol        `json:"protocol"`
	State    PortState       `json:"state"`
	Service  string          `json:"service,omitempty"`
	Banner   string          `json:"banner,omitempty"`
	Vulns    []Vulnerability `json:"vulns,omitempty"`
	ScanMs   int64           `json:"scan_ms"`
}

type Progress struct {
	Scanned   int     `json:"scanned"`
	Total     int     `json:"total"`
	Percent   float64 `json:"percent"`
	OpenCount int     `json:"open_count"`
}

type ScanComplete struct {
	Target    string    `json:"target"`
	Mode      ScanMode  `json:"mode"`
	Total     int       `json:"total_ports"`
	Open      int       `json:"open_ports"`
	DurationS float64   `json:"duration_s"`
	Start     time.Time `json:"start_time"`
	End       time.Time `json:"end_time"`
}

type Msg struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}

const (
	TypeScanRequest = "scan_request"
	TypePortResult  = "port_result"
	TypeProgress    = "progress"
	TypeComplete    = "scan_complete"
	TypeError       = "error"
	TypeCancel      = "cancel"
)
