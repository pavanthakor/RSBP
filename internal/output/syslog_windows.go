//go:build windows

package output

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	alertpkg "github.com/yoursec/rsbp/internal/alert"
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
	return &SyslogSink{name: "syslog", cfg: cfg, logger: logger}, nil
}

func (s *SyslogSink) Name() string { return s.name }

func (s *SyslogSink) Send(_ context.Context, a *alertpkg.ReverseShellAlert) error {
	if a == nil {
		return nil
	}
	msg := formatSyslogMessageWindows(a)

	var (
		conn net.Conn
		err  error
	)
	if s.cfg.EnableTLS {
		conn, err = tls.Dial("tcp", s.cfg.Address, &tls.Config{ServerName: s.cfg.ServerName})
	} else {
		conn, err = net.DialTimeout(s.cfg.Network, s.cfg.Address, 5*time.Second)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(msg + "\n"))
	return err
}

func (s *SyslogSink) Flush() error { return nil }
func (s *SyslogSink) Close() error { return nil }

func formatSyslogMessageWindows(a *alertpkg.ReverseShellAlert) string {
	mitre := make([]string, 0, len(a.MITRETechniques))
	for _, t := range a.MITRETechniques {
		mitre = append(mitre, t.ID)
	}
	return fmt.Sprintf(
		"RSBP[%s]: severity=%s score=%.2f pid=%d exe=%s remote=%s:%s country=%s mitre=%s",
		a.ID,
		strings.ToUpper(string(a.Severity)),
		a.Score,
		a.Process.PID,
		a.Process.ExePath,
		a.Network.RemoteIP,
		a.Network.RemotePort,
		a.Network.Country,
		strings.Join(mitre, ","),
	)
}
