// Package server refreshes the KRL from a source and serves it over HTTP.
package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/ssh"

	"github.com/vexxhost/ssh-krl/internal/krl"
	"github.com/vexxhost/ssh-krl/internal/source"
)

// Config configures a Server.
type Config struct {
	Source   source.Source
	Interval time.Duration
	// SkipInvalid publishes the valid entries when some are invalid, instead
	// of keeping the last good KRL.
	SkipInvalid bool
	Comment     string
	Logger      *slog.Logger
	Now         func() time.Time
}

// Server holds the current KRL.
type Server struct {
	cfg Config

	mu          sync.RWMutex
	data        []byte
	etag        string
	modTime     time.Time
	version     uint64
	contentHash string
	lastSuccess time.Time
	lastErr     error

	registry  *prometheus.Registry
	refreshes *prometheus.CounterVec
	lastOK    prometheus.Gauge
	entries   prometheus.Gauge
	invalid   prometheus.Gauge
	size      prometheus.Gauge
	krlVer    prometheus.Gauge
}

// New returns a Server. Call Run to start refreshing.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	s := &Server{cfg: cfg, registry: prometheus.NewRegistry()}
	s.refreshes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ssh_krl_refreshes_total", Help: "Refreshes from the source, by result.",
	}, []string{"result"})
	s.lastOK = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ssh_krl_last_success_timestamp_seconds", Help: "Time of the last successful refresh.",
	})
	s.entries = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ssh_krl_entries", Help: "Revocations in the published KRL.",
	})
	s.invalid = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ssh_krl_invalid_entries", Help: "Invalid entries found by the last refresh.",
	})
	s.size = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ssh_krl_bytes", Help: "Size of the published KRL.",
	})
	s.krlVer = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ssh_krl_version", Help: "Version number of the published KRL.",
	})
	s.registry.MustRegister(s.refreshes, s.lastOK, s.entries, s.invalid, s.size, s.krlVer,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return s
}

// Run refreshes immediately and then every interval until ctx is done.
func (s *Server) Run(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		if err := s.Refresh(ctx); err != nil && ctx.Err() == nil {
			s.cfg.Logger.Error("refresh failed; serving last good KRL", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Refresh reloads entries and republishes the KRL if its content changed.
func (s *Server) Refresh(ctx context.Context) error {
	err := s.refresh(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.lastErr = err
		s.refreshes.WithLabelValues("error").Inc()
		return err
	}
	s.lastErr = nil
	s.lastSuccess = s.cfg.Now()
	s.refreshes.WithLabelValues("success").Inc()
	s.lastOK.Set(float64(s.lastSuccess.Unix()))
	return nil
}

func (s *Server) refresh(ctx context.Context) error {
	entries, invalid, err := s.cfg.Source.Entries(ctx)
	if err != nil {
		return fmt.Errorf("reading %s: %w", s.cfg.Source, err)
	}
	s.invalid.Set(float64(len(invalid)))
	for _, e := range invalid {
		s.cfg.Logger.Warn("invalid revocation entry", "error", e)
	}
	if len(invalid) > 0 && !s.cfg.SkipInvalid {
		return fmt.Errorf("%d invalid entries: %w", len(invalid), errors.Join(invalid...))
	}

	now := s.cfg.Now()
	b := krl.NewBuilder(s.cfg.Comment)
	cas := map[string]ssh.PublicKey{}
	resolve := func(ref string) (ssh.PublicKey, error) {
		if key, ok := cas[ref]; ok {
			return key, nil
		}
		key, err := s.cfg.Source.ResolveCA(ctx, ref)
		if err != nil {
			return nil, err
		}
		cas[ref] = key
		return key, nil
	}
	for _, e := range entries {
		if e.Expired(now) {
			continue
		}
		var ca ssh.PublicKey
		if e.CA != "" {
			if ca, err = resolve(e.CA); err != nil {
				return fmt.Errorf("%s: %w", e.Name, err)
			}
		}
		switch {
		case e.Serial != nil:
			b.RevokeSerial(ca, *e.Serial)
		case e.KeyID != "":
			b.RevokeKeyID(ca, e.KeyID)
		case e.PublicKey != nil:
			b.RevokeKey(e.PublicKey)
		}
	}

	sum := sha256.Sum256(b.Marshal(0, time.Unix(0, 0)))
	content := hex.EncodeToString(sum[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	if content == s.contentHash && s.data != nil {
		return nil
	}
	version := krl.UnixSeconds(now)
	if version <= s.version {
		version = s.version + 1
	}
	data := b.Marshal(version, now)
	dataSum := sha256.Sum256(data)
	s.data = data
	s.etag = `"` + hex.EncodeToString(dataSum[:16]) + `"`
	s.modTime = now
	s.version = version
	s.contentHash = content
	s.entries.Set(float64(b.Len()))
	s.size.Set(float64(len(data)))
	s.krlVer.Set(float64(version))
	s.cfg.Logger.Info("published KRL", "version", version, "revocations", b.Len(), "bytes", len(data))
	return nil
}

// Handler serves /krl, /healthz, /readyz, /status and /metrics.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /krl", s.serveKRL)
	mux.HandleFunc("GET /healthz", s.serveHealth)
	mux.HandleFunc("GET /readyz", s.serveReady)
	mux.HandleFunc("GET /status", s.serveStatus)
	mux.Handle("GET /metrics", promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{}))
	return mux
}

func (s *Server) serveKRL(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	data, etag, modTime := s.data, s.etag, s.modTime
	s.mu.RUnlock()
	if data == nil {
		http.Error(w, "no KRL has been published yet", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", etag)
	http.ServeContent(w, r, "revoked.krl", modTime, bytes.NewReader(data))
}

func (s *Server) serveHealth(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintln(w, "ok")
}

// Status describes the published KRL and the last refresh.
type Status struct {
	Published   bool       `json:"published"`
	Version     uint64     `json:"version,omitempty"`
	Bytes       int        `json:"bytes,omitempty"`
	ETag        string     `json:"etag,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	Source      string     `json:"source"`
}

func (s *Server) status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Status{Published: s.data != nil, Version: s.version, Bytes: len(s.data), ETag: s.etag, Source: s.cfg.Source.String()}
	if !s.lastSuccess.IsZero() {
		t := s.lastSuccess
		st.LastSuccess = &t
	}
	if s.lastErr != nil {
		st.LastError = s.lastErr.Error()
	}
	return st
}

func (s *Server) serveStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.status())
}

func (s *Server) serveReady(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	published := s.data != nil
	s.mu.RUnlock()
	if !published {
		http.Error(w, "no KRL has been published yet", http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintln(w, "ok")
}
