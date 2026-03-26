package output

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	alertpkg "github.com/yoursec/rsbp/internal/alert"
	"go.uber.org/zap"
)

type ElasticsearchConfig struct {
	Addresses   []string `mapstructure:"addresses"`
	Username    string   `mapstructure:"username"`
	Password    string   `mapstructure:"password"`
	CertPath    string   `mapstructure:"cert_path"`
	SkipVerify  bool     `mapstructure:"skip_verify"`
	TemplateName string  `mapstructure:"template_name"`
}

type ESSink struct {
	client   *elasticsearch.Client
	logger   *zap.Logger
	name     string
	buffer   []*alertpkg.ReverseShellAlert
	mu       sync.Mutex
	ticker   *time.Ticker
	stopCh   chan struct{}
	stopped  chan struct{}
}

func NewESSink(cfg ElasticsearchConfig, logger *zap.Logger) (*ESSink, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if len(cfg.Addresses) == 0 {
		cfg.Addresses = []string{"http://127.0.0.1:9200"}
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.SkipVerify}
	if cfg.CertPath != "" {
		ca, err := os.ReadFile(cfg.CertPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(ca)
		tlsCfg.RootCAs = pool
	}

	client, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: cfg.Addresses,
		Username:  cfg.Username,
		Password:  cfg.Password,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	})
	if err != nil {
		return nil, err
	}

	s := &ESSink{
		client:  client,
		logger:  logger,
		name:    "elasticsearch",
		buffer:  make([]*alertpkg.ReverseShellAlert, 0, 100),
		ticker:  time.NewTicker(5 * time.Second),
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
	}

	go s.loop()
	if err := s.EnsureIndexTemplate(); err != nil {
		logger.Warn("failed to ensure index template", zap.Error(err))
	}
	return s, nil
}

func (e *ESSink) Name() string { return e.name }

func (e *ESSink) Send(_ context.Context, alert *alertpkg.ReverseShellAlert) error {
	if alert == nil {
		return nil
	}
	e.mu.Lock()
	e.buffer = append(e.buffer, alert)
	flushNow := len(e.buffer) >= 100
	e.mu.Unlock()
	if flushNow {
		return e.Flush()
	}
	return nil
}

func (e *ESSink) Flush() error {
	e.mu.Lock()
	batch := e.buffer
	e.buffer = make([]*alertpkg.ReverseShellAlert, 0, 100)
	e.mu.Unlock()

	if len(batch) == 0 {
		return nil
	}

	return e.retry(func() error {
		return e.bulkIndex(batch)
	})
}

func (e *ESSink) Close() error {
	close(e.stopCh)
	<-e.stopped
	return e.Flush()
}

func (e *ESSink) loop() {
	defer close(e.stopped)
	for {
		select {
		case <-e.stopCh:
			return
		case <-e.ticker.C:
			_ = e.Flush()
		}
	}
}

func (e *ESSink) bulkIndex(batch []*alertpkg.ReverseShellAlert) error {
	var body bytes.Buffer
	for _, a := range batch {
		index := "rsbp-alerts-" + a.Timestamp.UTC().Format("2006.01.02")
		meta := fmt.Sprintf("{\"index\":{\"_index\":\"%s\",\"_id\":\"%s\"}}\n", index, a.ID)
		body.WriteString(meta)
		payload, _ := json.Marshal(a)
		body.Write(payload)
		body.WriteByte('\n')
	}

	res, err := e.client.Bulk(strings.NewReader(body.String()))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.IsError() {
		return fmt.Errorf("bulk status: %s", res.Status())
	}
	return nil
}

func (e *ESSink) EnsureIndexTemplate() error {
	template := map[string]any{
		"index_patterns": []string{"rsbp-alerts-*"},
		"template": map[string]any{
			"settings": map[string]any{"index.lifecycle.name": "rsbp-ilm"},
			"mappings": map[string]any{
				"dynamic": true,
				"properties": map[string]any{
					"timestamp": map[string]any{"type": "date"},
					"severity":  map[string]any{"type": "keyword"},
					"score":     map[string]any{"type": "float"},
				},
			},
		},
	}
	payload, _ := json.Marshal(template)
	req, _ := http.NewRequest(http.MethodPut, "/_index_template/rsbp-alerts-template", bytes.NewReader(payload))
	res, err := e.client.Perform(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("template setup failed status %d", res.StatusCode)
	}

	ilm := []byte(`{"policy":{"phases":{"hot":{"actions":{}},"delete":{"min_age":"30d","actions":{"delete":{}}}}}}`)
	reqILM, _ := http.NewRequest(http.MethodPut, "/_ilm/policy/rsbp-ilm", bytes.NewReader(ilm))
	resILM, err := e.client.Perform(reqILM)
	if err != nil {
		return err
	}
	defer resILM.Body.Close()
	if resILM.StatusCode >= 300 {
		return fmt.Errorf("ilm setup failed status %d", resILM.StatusCode)
	}
	return nil
}

func (e *ESSink) retry(fn func() error) error {
	delays := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	var err error
	for i := 0; i < len(delays); i++ {
		err = fn()
		if err == nil {
			return nil
		}
		time.Sleep(delays[i])
	}
	return err
}
