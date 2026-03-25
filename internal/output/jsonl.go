package output

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	alertpkg "github.com/yoursec/rsbp/internal/alert"
	"go.uber.org/zap"
)

type JSONLSinkConfig struct {
	Path string `mapstructure:"path"`
}

type JSONLSink struct {
	name    string
	path    string
	logger  *zap.Logger
	mu      sync.Mutex
	file    *os.File
	dateKey string
	syncTk  *time.Ticker
	stopCh  chan struct{}
	stopped chan struct{}
}

func NewJSONLSink(cfg JSONLSinkConfig, logger *zap.Logger) (*JSONLSink, error) {
	if cfg.Path == "" {
		cfg.Path = "/var/log/rsbp/alerts.jsonl"
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o755); err != nil {
		return nil, err
	}
	ownerUID, ownerGID := resolveOwnerIDs()
	_ = os.Chmod(filepath.Dir(cfg.Path), 0o755)
	_ = os.Chown(filepath.Dir(cfg.Path), ownerUID, ownerGID)

	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	_ = f.Chmod(0o644)
	_ = f.Chown(ownerUID, ownerGID)

	s := &JSONLSink{
		name:    "jsonl",
		path:    cfg.Path,
		logger:  logger,
		file:    f,
		dateKey: time.Now().Format("2006-01-02"),
		syncTk:  time.NewTicker(time.Second),
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
	}

	go s.loopSync()
	return s, nil
}

func (s *JSONLSink) Name() string { return s.name }

func (s *JSONLSink) Send(_ context.Context, alert *alertpkg.ReverseShellAlert) error {
	if alert == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.rotateIfNeededLocked(); err != nil {
		return err
	}

	line, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	// Atomic write via temp file + rename to avoid partial JSON corruption.
	tmp := s.path + ".tmp"
	oldData, _ := os.ReadFile(s.path)
	if err := os.WriteFile(tmp, append(append(oldData, line...), '\n'), 0o644); err != nil {
		return err
	}
	ownerUID, ownerGID := resolveOwnerIDs()
	_ = os.Chown(tmp, ownerUID, ownerGID)
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}

	if s.file != nil {
		_ = s.file.Close()
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	_ = f.Chmod(0o644)
	_ = f.Chown(ownerUID, ownerGID)
	s.file = f
	return nil
}

func (s *JSONLSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	return s.file.Sync()
}

func (s *JSONLSink) Close() error {
	close(s.stopCh)
	<-s.stopped
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		_ = s.file.Sync()
		return s.file.Close()
	}
	return nil
}

func (s *JSONLSink) loopSync() {
	defer close(s.stopped)
	for {
		select {
		case <-s.stopCh:
			return
		case <-s.syncTk.C:
			_ = s.Flush()
		}
	}
}

func (s *JSONLSink) rotateIfNeededLocked() error {
	today := time.Now().Format("2006-01-02")
	if today == s.dateKey {
		return nil
	}
	if s.file != nil {
		_ = s.file.Sync()
		_ = s.file.Close()
	}

	rotated := filepath.Join(filepath.Dir(s.path), fmt.Sprintf("alerts.%s.jsonl", s.dateKey))
	if _, err := os.Stat(s.path); err == nil {
		_ = os.Rename(s.path, rotated)
	}

	s.dateKey = today
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	_ = f.Chmod(0o644)
	ownerUID, ownerGID := resolveOwnerIDs()
	_ = f.Chown(ownerUID, ownerGID)
	s.file = f

	return pruneOldRotations(filepath.Dir(s.path), 30)
}

func resolveOwnerIDs() (int, int) {
	uid := os.Getuid()
	gid := os.Getgid()
	if raw := strings.TrimSpace(os.Getenv("SUDO_UID")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			uid = parsed
		}
	}
	if raw := strings.TrimSpace(os.Getenv("SUDO_GID")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			gid = parsed
		}
	}
	return uid, gid
}

func pruneOldRotations(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "alerts.") && strings.HasSuffix(name, ".jsonl") {
			files = append(files, filepath.Join(dir, name))
		}
	}
	sort.Strings(files)
	if len(files) <= keep {
		return nil
	}
	for _, f := range files[:len(files)-keep] {
		_ = os.Remove(f)
	}
	return nil
}

func TailAlerts(path string, follow bool) (<-chan *alertpkg.ReverseShellAlert, error) {
	out := make(chan *alertpkg.ReverseShellAlert, 128)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	go func() {
		defer close(out)
		defer f.Close()

		reader := bufio.NewReader(f)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				break
			}
			var a alertpkg.ReverseShellAlert
			if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &a); err == nil {
				out <- &a
			}
		}

		if !follow {
			return
		}

		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return
		}
		defer watcher.Close()
		_ = watcher.Add(filepath.Dir(path))

		for ev := range watcher.Events {
			if ev.Op&(fsnotify.Write|fsnotify.Create) == 0 || filepath.Clean(ev.Name) != filepath.Clean(path) {
				continue
			}
			current, err := os.Open(path)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(current)
			for scanner.Scan() {
				var a alertpkg.ReverseShellAlert
				if json.Unmarshal(scanner.Bytes(), &a) == nil {
					out <- &a
				}
			}
			_ = current.Close()
		}
	}()

	return out, nil
}
