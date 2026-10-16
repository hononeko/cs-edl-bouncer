package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/hononeko/cs-edl-bouncer/pkg/store"
)

const (
	headerContentType     = "Content-Type"
	contentTypeTextPlain  = "text/plain; charset=utf-8"
	contentTypePrometheus = "text/plain; version=0.0.4; charset=utf-8"
)

// Server handles HTTP requests for EDL shards, health probes, and metrics.
type Server struct {
	store *store.Store
	mux   *http.ServeMux
}

// New constructs a new Server backed by the decision store.
func New(st *store.Store) *Server {
	s := &Server{
		store: st,
		mux:   http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

// Handler returns the underlying http.Handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /healthz", textHandler("ok\n"))
	s.mux.HandleFunc("GET /readyz", s.handleReadyz)
	s.mux.HandleFunc("GET /{$}", textHandler("ok\n"))
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)
	s.mux.HandleFunc("GET /lists/{shard}", s.handleListShard)
	s.mux.HandleFunc("GET /security/blocklist.txt", s.handleBlocklistMirror)
}

func textHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(headerContentType, contentTypeTextPlain)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if !s.store.Ready() {
		w.Header().Set(headerContentType, contentTypeTextPlain)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("waiting for first LAPI sync\n"))
		return
	}
	textHandler("ready\n")(w, r)
}

func (s *Server) serveShard(w http.ResponseWriter, r *http.Request, name string) {
	data, ok := s.store.GetShard(name)
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set(headerContentType, contentTypeTextPlain)
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- served content is plain-text IP/CIDR blocklists
	_, _ = w.Write(data)
}

func (s *Server) handleListShard(w http.ResponseWriter, r *http.Request) {
	shard := r.PathValue("shard")
	if shard == "" || strings.Contains(shard, "/") || strings.Contains(shard, "..") {
		http.NotFound(w, r)
		return
	}
	s.serveShard(w, r, shard)
}

func (s *Server) handleBlocklistMirror(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := "all.txt"
	if q.Has("ipv4only") {
		target = "ipv4.txt"
	} else if q.Has("ipv6only") {
		target = "ipv6.txt"
	}
	s.serveShard(w, r, target)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := s.store.GetMetrics()

	metrics := []struct {
		name  string
		help  string
		mType string
		val   int64
	}{
		{"cs_edl_decisions_raw", "Number of raw decisions tracked", "gauge", m.RawDecisions},
		{"cs_edl_entries_ipv4", "Number of aggregated/formatted IPv4 entries", "gauge", m.IPv4Entries},
		{"cs_edl_entries_ipv6", "Number of aggregated/formatted IPv6 entries", "gauge", m.IPv6Entries},
		{"cs_edl_shards_ipv4", "Number of IPv4 shards generated", "gauge", m.IPv4Shards},
		{"cs_edl_shards_ipv6", "Number of IPv6 shards generated", "gauge", m.IPv6Shards},
		{"cs_edl_shard_capacity_ipv4", "Maximum IPv4 entries across all shards (0 = unlimited)", "gauge", m.IPv4Capacity},
		{"cs_edl_shard_capacity_ipv6", "Maximum IPv6 entries across all shards (0 = unlimited)", "gauge", m.IPv6Capacity},
		{"cs_edl_overflow_entries_ipv4", "IPv4 entries left out of the shards because of the shard cap", "gauge", m.IPv4OverflowEntries},
		{"cs_edl_overflow_entries_ipv6", "IPv6 entries left out of the shards because of the shard cap", "gauge", m.IPv6OverflowEntries},
		{"cs_edl_sync_success_total", "Total successful LAPI stream syncs", "counter", m.SyncSuccessTotal},
		{"cs_edl_sync_failure_total", "Total failed LAPI stream syncs", "counter", m.SyncFailureTotal},
		{"cs_edl_last_sync_timestamp_seconds", "Unix timestamp of the last successful sync", "gauge", m.LastSyncTimestampSecs},
	}

	var b strings.Builder
	for _, metric := range metrics {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", metric.name, metric.help, metric.name, metric.mType, metric.name, metric.val)
	}

	w.Header().Set(headerContentType, contentTypePrometheus)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}
