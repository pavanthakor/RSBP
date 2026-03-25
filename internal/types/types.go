package types

import "time"

// SyscallEvent is the canonical telemetry message emitted by eBPF and consumed by userspace.
// It preserves kernel-level fidelity while remaining sink-agnostic.
type SyscallEvent struct {
	PID            uint32
	PPID           uint32
	UID            uint32
	GID            uint32
	SyscallNr      uint32
	FD             int32
	RemoteIP4      uint32
	RemoteIP6      [16]byte
	RemotePort     uint16
	Family         uint16
	TimestampNS    uint64
	Comm           [16]byte
	ExecPath       [256]byte
	Args           [512]byte
	HasExecve      uint8
	HasSocket      uint8
	HasConnect     uint8
	HasDup2Stdio   uint8
	ForkParentPID  uint32
	SuspiciousMask uint32
	ReceivedAt     time.Time `json:"-" yaml:"-"`
}

type AlertSeverity string

const (
	SeverityLow      AlertSeverity = "Low"
	SeverityMedium   AlertSeverity = "Medium"
	SeverityHigh     AlertSeverity = "High"
	SeverityCritical AlertSeverity = "Critical"
)

type ProcessContext struct {
	PID     uint32 `json:"pid" yaml:"pid"`
	PPID    uint32 `json:"ppid" yaml:"ppid"`
	UID     uint32 `json:"uid" yaml:"uid"`
	GID     uint32 `json:"gid" yaml:"gid"`
	Comm    string `json:"comm" yaml:"comm"`
	Exe     string `json:"exe" yaml:"exe"`
	Cmdline string `json:"cmdline" yaml:"cmdline"`
}

type NetworkContext struct {
	RemoteIP       string `json:"remote_ip" yaml:"remote_ip"`
	RemotePort     uint16 `json:"remote_port" yaml:"remote_port"`
	Protocol       string `json:"protocol" yaml:"protocol"`
	GeoIPCountry   string `json:"geoip_country" yaml:"geoip_country"`
	GeoIPCity      string `json:"geoip_city" yaml:"geoip_city"`
	ASN            string `json:"asn" yaml:"asn"`
	AbuseIPDBScore int    `json:"abuseipdb_score" yaml:"abuseipdb_score"`
}

type ForensicsArtifact struct {
	FDDump       bool   `json:"fd_dump" yaml:"fd_dump"`
	FDDumpRef    string `json:"fd_dump_ref" yaml:"fd_dump_ref"`
	CmdlineDump  bool   `json:"cmdline_dump" yaml:"cmdline_dump"`
	CmdlineRef   string `json:"cmdline_ref" yaml:"cmdline_ref"`
	SocketDump   bool   `json:"socket_dump" yaml:"socket_dump"`
	SocketRef    string `json:"socket_ref" yaml:"socket_ref"`
	MiniPCAPDump bool   `json:"mini_pcap_dump" yaml:"mini_pcap_dump"`
	MiniPCAPRef  string `json:"mini_pcap_ref" yaml:"mini_pcap_ref"`
}

// ReverseShellAlert is the normalized, enriched, and correlatable security alert envelope.
// Field names mirror the architecture contract so every sink receives consistent payloads.
type ReverseShellAlert struct {
	AlertID       string            `json:"alert_id" yaml:"alert_id"`
	Timestamp     time.Time         `json:"timestamp" yaml:"timestamp"`
	HostID        string            `json:"host_id" yaml:"host_id"`
	SessionID     string            `json:"session_id" yaml:"session_id"`
	EventChain    []string          `json:"event_chain" yaml:"event_chain"`
	MITREAttack   []string          `json:"mitre_attack" yaml:"mitre_attack"`
	Severity      AlertSeverity     `json:"severity" yaml:"severity"`
	Confidence    float64           `json:"confidence" yaml:"confidence"`
	RuleID        string            `json:"rule_id" yaml:"rule_id"`
	Description   string            `json:"description" yaml:"description"`
	Process       ProcessContext    `json:"process" yaml:"process"`
	Network       NetworkContext    `json:"network" yaml:"network"`
	Forensics     ForensicsArtifact `json:"forensics" yaml:"forensics"`
	CorrelationID string            `json:"correlation_id" yaml:"correlation_id"`
	Metadata      map[string]string `json:"metadata" yaml:"metadata"`
	PipelineStart time.Time         `json:"-" yaml:"-"`
}
