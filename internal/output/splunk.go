package output

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	alertpkg "github.com/yoursec/rsbp/internal/alert"
	"go.uber.org/zap"
)

type SplunkConfig struct {
	Endpoint   string `mapstructure:"endpoint"`
	Token      string `mapstructure:"token"`
	SkipVerify bool   `mapstructure:"skip_verify"`
	Hostname   string `mapstructure:"hostname"`
}

type SplunkSink struct {
	name    string
	client  *http.Client
	cfg     SplunkConfig
	logger  *zap.Logger
	mu      sync.Mutex
	buffer  []*alertpkg.ReverseShellAlert
	ticker  *time.Ticker
	stopCh  chan struct{}
	stopped chan struct{}
}

func NewSplunkSink(cfg SplunkConfig, logger *zap.Logger) (*SplunkSink, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("splunk endpoint is empty")
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	s := &SplunkSink{
		name:    "splunk",
		cfg:     cfg,
		logger:  logger,
		client:  &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.SkipVerify}}},
		buffer:  make([]*alertpkg.ReverseShellAlert, 0, 50),
		ticker:  time.NewTicker(5 * time.Second),
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
	}
	go s.loop()
	return s, nil
}

func (s *SplunkSink) Name() string { return s.name }

func (s *SplunkSink) Send(_ context.Context, a *alertpkg.ReverseShellAlert) error {
	if a == nil {
		return nil
	}
	s.mu.Lock()
	s.buffer = append(s.buffer, a)
	flush := len(s.buffer) >= 50
	s.mu.Unlock()
	if flush {
		return s.Flush()
	}
	return nil
}

func (s *SplunkSink) Flush() error {
	s.mu.Lock()
	batch := s.buffer
	s.buffer = make([]*alertpkg.ReverseShellAlert, 0, 50)
	s.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}

	return retryWithBackoff(func() error {
		payload := make([]map[string]any, 0, len(batch))
		for _, a := range batch {
			payload = append(payload, map[string]any{
				"time":       a.Timestamp.Unix(),
				"sourcetype": "rsbp:alert",
				"source":     "rsbp-agent",
				"host":       s.cfg.Hostname,
				"event":      a,
			})
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, s.cfg.Endpoint, bytes.NewReader(body))
		req.Header.Set("Authorization", "Splunk "+s.cfg.Token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("splunk status %d", resp.StatusCode)
		}
		return nil
	})
}

func (s *SplunkSink) Close() error {
	close(s.stopCh)
	<-s.stopped
	return s.Flush()
}

func (s *SplunkSink) loop() {
	defer close(s.stopped)
	for {
		select {
		case <-s.stopCh:
			return
		case <-s.ticker.C:
			_ = s.Flush()
		}
	}
}

func retryWithBackoff(fn func() error) error {
	delays := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	var err error
	for _, d := range delays {
		err = fn()
		if err == nil {
			return nil
		}
		jitter := time.Duration(rand.Int63n(int64(250 * time.Millisecond)))
		time.Sleep(d + jitter)
	}
	return err
}
