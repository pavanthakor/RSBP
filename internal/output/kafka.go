package output

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/plain"
	alertpkg "github.com/yoursec/rsbp/internal/alert"
	"go.uber.org/zap"
)

type KafkaConfig struct {
	Brokers   []string `mapstructure:"brokers"`
	Topic     string   `mapstructure:"topic"`
	Username  string   `mapstructure:"username"`
	Password  string   `mapstructure:"password"`
	EnableTLS bool     `mapstructure:"enable_tls"`
	EnableSASL bool    `mapstructure:"enable_sasl"`
}

type KafkaSink struct {
	name   string
	writer *kafka.Writer
	logger *zap.Logger
}

func NewKafkaSink(cfg KafkaConfig, logger *zap.Logger) (*KafkaSink, error) {
	if len(cfg.Brokers) == 0 {
		cfg.Brokers = []string{"127.0.0.1:9092"}
	}
	if cfg.Topic == "" {
		cfg.Topic = "rsbp-alerts"
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	dialer := &kafka.Dialer{Timeout: 5 * time.Second}
	if cfg.EnableTLS {
		dialer.TLS = &tls.Config{}
	}
	if cfg.EnableSASL {
		dialer.SASLMechanism = plain.Mechanism{Username: cfg.Username, Password: cfg.Password}
	}

	w := &kafka.Writer{
		Addr:         kafka.TCP(cfg.Brokers...),
		Topic:        cfg.Topic,
		Balancer:     &kafka.Hash{},
		Async:        true,
		BatchSize:    100,
		BatchTimeout: time.Second,
		RequiredAcks: kafka.RequireOne,
		Transport: &kafka.Transport{Dial: func(ctx context.Context, network string, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		}},
	}

	return &KafkaSink{name: "kafka", writer: w, logger: logger}, nil
}

func (k *KafkaSink) Name() string { return k.name }

func (k *KafkaSink) Send(ctx context.Context, a *alertpkg.ReverseShellAlert) error {
	if a == nil {
		return nil
	}
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}

	msg := kafka.Message{
		Key:   []byte(strconv.FormatUint(uint64(a.Process.PID), 10)),
		Value: body,
		Time:  a.Timestamp,
	}
	if err := k.writer.WriteMessages(ctx, msg); err != nil {
		return fmt.Errorf("kafka write: %w", err)
	}
	return nil
}

func (k *KafkaSink) Flush() error { return nil }

func (k *KafkaSink) Close() error {
	if k.writer == nil {
		return nil
	}
	return k.writer.Close()
}
