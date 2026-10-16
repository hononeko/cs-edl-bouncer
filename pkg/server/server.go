package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/hononeko/cs-edl-bouncer/pkg/store"
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
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /readyz", s.handleReadyz)
	s.mux.HandleFunc("GET /{$}", s.handleRoot)
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)
	s.mux.HandleFunc("GET /lists/{shard}", s.handleListShard)
	s.mux.HandleFunc("GET /security/blocklist.txt", s.handleBlocklistMirror)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleListShard(w http.ResponseWriter, r *http.Request) {
	shard := r.PathValue("shard")
	if shard == "" || strings.Contains(shard, "/") || strings.Contains(shard, "..") {
		http.NotFound(w, r)
		return
	}

	data, ok := s.store.GetShard(shard)
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- served content is plain-text IP/CIDR blocklists
	_, _ = w.Write(data)
}

func (s *Server) handleBlocklistMirror(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := "all.txt"
	if q.Has("ipv4only") {
		target = "ipv4.txt"
	} else if q.Has("ipv6only") {
		target = "ipv6.txt"
	}

	data, ok := s.store.GetShard(target)
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- served content is plain-text IP/CIDR blocklists
	_, _ = w.Write(data)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := s.store.GetMetrics()

	var b strings.Builder
	b.WriteString("# HELP cs_edl_decisions_raw Number of raw decisions tracked\n")
	b.WriteString("# TYPE cs_edl_decisions_raw gauge\n")
	fmt.Fprintf(&b, "cs_edl_decisions_raw %d\n", m.RawDecisions)

	b.WriteString("# HELP cs_edl_entries_ipv4 Number of aggregated/formatted IPv4 entries\n")
	b.WriteString("# TYPE cs_edl_entries_ipv4 gauge\n")
	fmt.Fprintf(&b, "cs_edl_entries_ipv4 %d\n", m.IPv4Entries)

	b.WriteString("# HELP cs_edl_entries_ipv6 Number of aggregated/formatted IPv6 entries\n")
	b.WriteString("# TYPE cs_edl_entries_ipv6 gauge\n")
	fmt.Fprintf(&b, "cs_edl_entries_ipv6 %d\n", m.IPv6Entries)

	b.WriteString("# HELP cs_edl_shards_ipv4 Number of IPv4 shards generated\n")
	b.WriteString("# TYPE cs_edl_shards_ipv4 gauge\n")
	fmt.Fprintf(&b, "cs_edl_shards_ipv4 %d\n", m.IPv4Shards)

	b.WriteString("# HELP cs_edl_shards_ipv6 Number of IPv6 shards generated\n")
	b.WriteString("# TYPE cs_edl_shards_ipv6 gauge\n")
	fmt.Fprintf(&b, "cs_edl_shards_ipv6 %d\n", m.IPv6Shards)

	b.WriteString("# HELP cs_edl_sync_success_total Total successful LAPI stream syncs\n")
	b.WriteString("# TYPE cs_edl_sync_success_total counter\n")
	fmt.Fprintf(&b, "cs_edl_sync_success_total %d\n", m.SyncSuccessTotal)

	b.WriteString("# HELP cs_edl_sync_failure_total Total failed LAPI stream syncs\n")
	b.WriteString("# TYPE cs_edl_sync_failure_total counter\n")
	fmt.Fprintf(&b, "cs_edl_sync_failure_total %d\n", m.SyncFailureTotal)

	b.WriteString("# HELP cs_edl_last_sync_timestamp_seconds Unix timestamp of the last successful sync\n")
	b.WriteString("# TYPE cs_edl_last_sync_timestamp_seconds gauge\n")
	fmt.Fprintf(&b, "cs_edl_last_sync_timestamp_seconds %d\n", m.LastSyncTimestampSecs)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}
