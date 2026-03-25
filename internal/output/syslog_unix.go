//go:build !windows

package output

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/syslog"
	"os"
	"strconv"
	"strings"
	"time"

	alertpkg "github.com/yoursec/rsbp/internal/alert"
	"github.com/yoursec/rsbp/internal/types"
	"go.uber.org/zap"
)

type SyslogConfig struct {
	Network    string `mapstructure:"network"`
	Address    string `mapstructure:"address"`
	Tag        string `mapstructure:"tag"`
	EnableTLS  bool   `mapstructure:"enable_tls"`
	ServerName string `mapstructure:"server_name"`
}

type SyslogSink struct {
	name   string
	cfg    SyslogConfig
	logger *zap.Logger
	writer *syslog.Writer
}

func NewSyslogSink(cfg SyslogConfig, logger *zap.Logger) (*SyslogSink, error) {
	if cfg.Network == "" {
		cfg.Network = "udp"
	}
	if cfg.Address == "" {
		cfg.Address = "127.0.0.1:514"
	}
	if cfg.Tag == "" {
		cfg.Tag = "RSBP"
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	s := &SyslogSink{name: "syslog", cfg: cfg, logger: logger}
	if !cfg.EnableTLS {
		w, err := syslog.Dial(cfg.Network, cfg.Address, syslog.LOG_LOCAL0|syslog.LOG_INFO, cfg.Tag)
		if err != nil {
			return nil, err
		}
		s.writer = w
	}
	return s, nil
}

func (s *SyslogSink) Name() string { return s.name }

func (s *SyslogSink) Send(_ context.Context, a *alertpkg.ReverseShellAlert) error {
	if a == nil {
		return nil
	}
	msg := formatSyslogMessage(a)
	if s.cfg.EnableTLS {
		return s.sendTLS(msg)
	}

	sev := mapSeverity(a.Severity)
	switch sev {
	case syslog.LOG_CRIT:
		return s.writer.Crit(msg)
	case syslog.LOG_WARNING:
		return s.writer.Warning(msg)
	default:
		return s.writer.Info(msg)
	}
}

func (s *SyslogSink) Flush() error { return nil }

func (s *SyslogSink) Close() error {
	if s.writer != nil {
		return s.writer.Close()
	}
	return nil
}

func (s *SyslogSink) sendTLS(msg string) error {
	conn, err := tls.Dial("tcp", s.cfg.Address, &tls.Config{ServerName: s.cfg.ServerName})
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(msg + "\n"))
	return err
}

func mapSeverity(sev types.AlertSeverity) syslog.Priority {
	s := strings.ToLower(string(sev))
	switch s {
	case "critical":
		return syslog.LOG_CRIT
	case "high":
		return syslog.LOG_WARNING
	case "medium":
		return syslog.LOG_NOTICE
	default:
		return syslog.LOG_INFO
	}
}

func formatSyslogMessage(a *alertpkg.ReverseShellAlert) string {
	mitre := make([]string, 0, len(a.MITRETechniques))
	for _, t := range a.MITRETechniques {
		mitre = append(mitre, t.ID)
	}
	hostname := a.HostInfo.Hostname
	if strings.TrimSpace(hostname) == "" {
		hostname = "-"
	}
	ts := a.Timestamp.UTC().Format(time.RFC3339)
	procID := strconv.Itoa(os.Getpid())
	msgID := "rsbp-alert"
	structured := fmt.Sprintf(
		"[rsbp@32473 alert_id=\"%s\" severity=\"%s\" score=\"%.2f\" pid=\"%d\" remote_ip=\"%s\" remote_port=\"%s\" mitre=\"%s\"]",
		a.ID,
		strings.ToUpper(string(a.Severity)),
		a.Score,
		a.Process.PID,
		a.Network.RemoteIP,
		a.Network.RemotePort,
		strings.Join(mitre, ","),
	)
	msg := fmt.Sprintf("exe=%s country=%s pattern=%s", a.Process.ExePath, a.Network.Country, a.Pattern)
	return fmt.Sprintf("<134>1 %s %s RSBP %s %s %s %s", ts, hostname, procID, msgID, structured, msg)
}
