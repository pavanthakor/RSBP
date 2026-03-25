package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	alertpkg "github.com/yoursec/rsbp/internal/alert"
	"go.uber.org/zap"
)

type Config struct {
	Enabled       bool
	Listen        string
	MetricsListen string
	BearerToken   string
	AlertsPath    string
}

type WhitelistEntry struct {
	ID          string    `json:"id"`
	IPs         []string  `json:"ips,omitempty"`
	Paths       []string  `json:"paths,omitempty"`
	Users       []uint32  `json:"users,omitempty"`
	ProcessName []string  `json:"process_names,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type Server struct {
	cfg                Config
	logger             *zap.Logger
	start              time.Time
	eventsCount        *atomic.Uint64
	healthProvider     func() map[string]any
	deepHealthProvider func() map[string]any
	statsProvider      func() map[string]any
	configProvider     func() any
	reloadFn           func(context.Context) ([]string, error)
	testFn             func(context.Context) error

	wlMu      sync.RWMutex
	whitelist map[string]WhitelistEntry
}

func NewServer(cfg Config, logger *zap.Logger, eventsCount *atomic.Uint64, healthProvider func() map[string]any, deepHealthProvider func() map[string]any, statsProvider func() map[string]any, configProvider func() any, reloadFn func(context.Context) ([]string, error), testFn func(context.Context) error) *Server {
	if logger == nil {
		logger = zap.NewNop()
	}
	if eventsCount == nil {
		eventsCount = &atomic.Uint64{}
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:9001"
	}
	if cfg.MetricsListen == "" {
		cfg.MetricsListen = "0.0.0.0:9090"
	}
	if cfg.AlertsPath == "" {
		cfg.AlertsPath = "/var/log/rsbp/alerts.jsonl"
	}
	return &Server{
		cfg:                cfg,
		logger:             logger,
		start:              time.Now(),
		eventsCount:        eventsCount,
		healthProvider:     healthProvider,
		deepHealthProvider: deepHealthProvider,
		statsProvider:      statsProvider,
		configProvider:     configProvider,
		reloadFn:           reloadFn,
		testFn:             testFn,
		whitelist:          map[string]WhitelistEntry{},
	}
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(s.loggingMiddleware)
	r.Use(s.authMiddleware)

	r.Get("/health", s.handleHealth)
	r.Get("/health/deep", s.handleHealthDeep)
	r.Get("/stats", s.handleStats)
	r.Get("/debug/config", s.handleDebugConfig)
	r.Get("/alerts", s.handleAlerts)
	r.Get("/alerts/{id}", s.handleAlertByID)
	r.Get("/whitelist", s.handleWhitelistGet)
	r.Post("/whitelist", s.handleWhitelistPost)
	r.Delete("/whitelist/{id}", s.handleWhitelistDelete)
	r.Post("/reload", s.handleReload)
	r.Get("/metrics", s.handleMetricsRedirect)
	r.Post("/test", s.handleTest)

	return r
}

func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{Addr: s.cfg.Listen, Handler: s.Handler()}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	health := map[string]any{
		"status": "ok",
		"uptime": time.Since(s.start).String(),
	}
	if s.healthProvider != nil {
		for k, v := range s.healthProvider() {
			health[k] = v
		}
	}
	s.writeJSON(w, http.StatusOK, health)
}

func (s *Server) handleHealthDeep(w http.ResponseWriter, _ *http.Request) {
	deep := map[string]any{
		"status":           "ok",
		"uptime":           time.Since(s.start).String(),
		"events_processed": s.eventsCount.Load(),
	}
	if s.deepHealthProvider != nil {
		for k, v := range s.deepHealthProvider() {
			deep[k] = v
		}
	} else if s.healthProvider != nil {
		for k, v := range s.healthProvider() {
			deep[k] = v
		}
	}
	s.writeJSON(w, http.StatusOK, deep)
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	stats := map[string]any{
		"uptime":           time.Since(s.start).String(),
		"events_processed": s.eventsCount.Load(),
	}
	if s.statsProvider != nil {
		for k, v := range s.statsProvider() {
			stats[k] = v
		}
	}
	s.writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleDebugConfig(w http.ResponseWriter, _ *http.Request) {
	if s.configProvider == nil {
		s.writeError(w, http.StatusNotImplemented, "config debug provider not configured")
		return
	}
	payload := s.configProvider()
	if m, ok := payload.(map[string]any); ok {
		if _, hasActive := m["active_config"]; hasActive {
			s.writeJSON(w, http.StatusOK, m)
			return
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"active_config": payload})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	alerts, err := readLastAlerts(s.cfg.AlertsPath, limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, alerts)
}

func (s *Server) handleAlertByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "missing alert id")
		return
	}
	alerts, err := readLastAlerts(s.cfg.AlertsPath, 5000)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, a := range alerts {
		if a != nil && a.ID == id {
			s.writeJSON(w, http.StatusOK, a)
			return
		}
	}
	s.writeError(w, http.StatusNotFound, "alert not found")
}

func (s *Server) handleWhitelistGet(w http.ResponseWriter, _ *http.Request) {
	s.wlMu.RLock()
	items := make([]WhitelistEntry, 0, len(s.whitelist))
	for _, v := range s.whitelist {
		items = append(items, v)
	}
	s.wlMu.RUnlock()
	s.writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleWhitelistPost(w http.ResponseWriter, r *http.Request) {
	var in WhitelistEntry
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	in.ID = fmt.Sprintf("wl-%d", time.Now().UnixNano())
	in.CreatedAt = time.Now().UTC()
	s.wlMu.Lock()
	s.whitelist[in.ID] = in
	s.wlMu.Unlock()
	s.writeJSON(w, http.StatusCreated, in)
}

func (s *Server) handleWhitelistDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "missing whitelist id")
		return
	}
	s.wlMu.Lock()
	_, ok := s.whitelist[id]
	if ok {
		delete(s.whitelist, id)
	}
	s.wlMu.Unlock()
	if !ok {
		s.writeError(w, http.StatusNotFound, "whitelist entry not found")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if s.reloadFn == nil {
		s.writeJSON(w, http.StatusOK, map[string]any{"reloaded": false, "reason": "reload callback not configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	reloaded, err := s.reloadFn(ctx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(reloaded) == 0 {
		reloaded = []string{"whitelist", "detection", "outputs"}
	}
	for _, subsystem := range reloaded {
		s.logger.Info("reload applied", zap.String("subsystem", subsystem))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"reloaded": reloaded})
}

func (s *Server) handleMetricsRedirect(w http.ResponseWriter, _ *http.Request) {
	http.Redirect(w, &http.Request{}, "http://"+s.cfg.MetricsListen+"/metrics", http.StatusTemporaryRedirect)
}

func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	if s.testFn == nil {
		s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "test hook not configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.testFn(ctx); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeError(w http.ResponseWriter, code int, msg string) {
	s.writeJSON(w, code, map[string]any{"error": msg, "code": code})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	if s.cfg.BearerToken == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		expected := "Bearer " + s.cfg.BearerToken
		if auth != expected {
			s.writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Info("api request",
			zap.String("ip", clientIP(r)),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Duration("duration", time.Since(start)),
		)
	})
}

func clientIP(r *http.Request) string {
	xff := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0])
	if xff != "" {
		return xff
	}
	return r.RemoteAddr
}

func readLastAlerts(path string, limit int) ([]*alertpkg.ReverseShellAlert, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	alerts := make([]*alertpkg.ReverseShellAlert, 0, limit)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var a alertpkg.ReverseShellAlert
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			continue
		}
		alerts = append(alerts, &a)
		if len(alerts) > limit {
			alerts = alerts[len(alerts)-limit:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return alerts, nil
}
