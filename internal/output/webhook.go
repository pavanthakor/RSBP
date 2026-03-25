package output

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	alertpkg "github.com/yoursec/rsbp/internal/alert"
	"go.uber.org/zap"
)

type WebhookConfig struct {
	URL     string            `mapstructure:"url"`
	Secret  string            `mapstructure:"secret"`
	Headers map[string]string `mapstructure:"headers"`
}

type WebhookSink struct {
	name   string
	cfg    WebhookConfig
	client *http.Client
	logger *zap.Logger
}

func NewWebhookSink(cfg WebhookConfig, logger *zap.Logger) (*WebhookSink, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("webhook url is empty")
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &WebhookSink{
		name:   "webhook",
		cfg:    cfg,
		client: &http.Client{Timeout: 5 * time.Second},
		logger: logger,
	}, nil
}

func (w *WebhookSink) Name() string { return w.name }

func (w *WebhookSink) Send(ctx context.Context, alert *alertpkg.ReverseShellAlert) error {
	if alert == nil {
		return nil
	}
	body, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	return retryWithJitter(3, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if w.cfg.Secret != "" {
			sig := hmacSHA256Hex(w.cfg.Secret, body)
			req.Header.Set("X-RSBP-Signature", "sha256="+sig)
		}
		for k, v := range w.cfg.Headers {
			req.Header.Set(k, v)
		}

		resp, err := w.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("webhook status %d", resp.StatusCode)
		}
		return nil
	})
}

func (w *WebhookSink) Flush() error { return nil }

func (w *WebhookSink) Close() error { return nil }

func hmacSHA256Hex(secret string, data []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func retryWithJitter(attempts int, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		base := time.Duration(250*(i+1)) * time.Millisecond
		jitter := time.Duration(rand.Int63n(int64(250 * time.Millisecond)))
		time.Sleep(base + jitter)
	}
	return err
}
