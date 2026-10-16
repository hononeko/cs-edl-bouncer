package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hononeko/cs-edl-bouncer/pkg/crowdsec"
	"github.com/hononeko/cs-edl-bouncer/pkg/store"
)

func setupTestServer() *Server {
	st := store.NewStore(store.Options{SupportedTypes: []string{"ban"}, ShardSize: 9500, MinIPv4Shards: 3, MinIPv6Shards: 1, AggregateCIDR: true})
	st.ProcessStream(true, &crowdsec.StreamResponse{
		New: []crowdsec.Decision{
			{ID: 1, Type: "ban", Value: "10.0.0.1"},
			{ID: 2, Type: "ban", Value: "2001:db8::1"},
		},
	})
	return New(st)
}

func assertGET(t *testing.T, handler http.Handler, path string, wantStatus int, wantContains, wantNotContains []string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != wantStatus {
		t.Fatalf("%s returned status %d, expected %d", path, rec.Code, wantStatus)
	}
	body := rec.Body.String()
	for _, s := range wantContains {
		if !strings.Contains(body, s) {
			t.Errorf("%s response missing %q:\n%s", path, s, body)
		}
	}
	for _, s := range wantNotContains {
		if strings.Contains(body, s) {
			t.Errorf("%s response unexpectedly contains %q:\n%s", path, s, body)
		}
	}
	return rec
}

func TestHealthEndpoints(t *testing.T) {
	srv := setupTestServer()
	handler := srv.Handler()

	paths := []string{"/healthz", "/readyz", "/"}
	for _, p := range paths {
		assertGET(t, handler, p, http.StatusOK, nil, nil)
	}
}

func TestReadyzWaitsForFirstSync(t *testing.T) {
	st := store.NewStore(store.Options{ShardSize: 9500, MinIPv4Shards: 3, MinIPv6Shards: 1, AggregateCIDR: true})
	handler := New(st).Handler()

	assertGET(t, handler, "/readyz", http.StatusServiceUnavailable, nil, nil)
	assertGET(t, handler, "/healthz", http.StatusOK, nil, nil)

	st.RecordSyncFailure()
	assertGET(t, handler, "/readyz", http.StatusServiceUnavailable, nil, nil)

	st.ProcessStream(true, &crowdsec.StreamResponse{})
	assertGET(t, handler, "/readyz", http.StatusOK, []string{"ready"}, nil)

	// A later failure keeps serving the last good lists.
	st.RecordSyncFailure()
	assertGET(t, handler, "/readyz", http.StatusOK, nil, nil)
}

func TestListsEndpoint(t *testing.T) {
	srv := setupTestServer()
	handler := srv.Handler()

	tests := []struct {
		name         string
		path         string
		wantStatus   int
		wantContains []string
	}{
		{
			name:         "serve existing shard",
			path:         "/lists/ipv4-0.txt",
			wantStatus:   http.StatusOK,
			wantContains: []string{"10.0.0.1"},
		},
		{
			name:         "serve combined list",
			path:         "/lists/all.txt",
			wantStatus:   http.StatusOK,
			wantContains: []string{"10.0.0.1", "2001:db8::1"},
		},
		{
			name:       "unknown shard returns 404",
			path:       "/lists/nonexistent.txt",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "path traversal attempt returns 404",
			path:       "/lists/..%2fpasswd",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := assertGET(t, handler, tc.path, tc.wantStatus, tc.wantContains, nil)
			if tc.wantStatus == http.StatusOK && !strings.Contains(rec.Header().Get("Content-Type"), "text/plain") {
				t.Errorf("expected text/plain Content-Type, got %s", rec.Header().Get("Content-Type"))
			}
		})
	}
}

func TestSecurityBlocklistEndpoint(t *testing.T) {
	srv := setupTestServer()
	handler := srv.Handler()

	tests := []struct {
		name            string
		path            string
		wantContains    []string
		wantNotContains []string
	}{
		{
			name:         "default serves all.txt",
			path:         "/security/blocklist.txt",
			wantContains: []string{"10.0.0.1", "2001:db8::1"},
		},
		{
			name:            "ipv4only param serves ipv4.txt",
			path:            "/security/blocklist.txt?ipv4only",
			wantContains:    []string{"10.0.0.1"},
			wantNotContains: []string{"2001:db8::1"},
		},
		{
			name:            "ipv6only param serves ipv6.txt",
			path:            "/security/blocklist.txt?ipv6only",
			wantContains:    []string{"2001:db8::1"},
			wantNotContains: []string{"10.0.0.1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertGET(t, handler, tc.path, http.StatusOK, tc.wantContains, tc.wantNotContains)
		})
	}
}

func TestMetricsEndpoint(t *testing.T) {
	srv := setupTestServer()
	handler := srv.Handler()

	requiredMetrics := []string{
		"cs_edl_decisions_raw 2",
		"cs_edl_entries_ipv4 1",
		"cs_edl_entries_ipv6 1",
		"cs_edl_shards_ipv4 3",
		"cs_edl_shards_ipv6 1",
		"cs_edl_shard_capacity_ipv4 0",
		"cs_edl_shard_capacity_ipv6 0",
		"cs_edl_overflow_entries_ipv4 0",
		"cs_edl_overflow_entries_ipv6 0",
		"cs_edl_sync_success_total 1",
		"cs_edl_sync_failure_total 0",
		"cs_edl_last_sync_timestamp_seconds",
	}

	rec := assertGET(t, handler, "/metrics", http.StatusOK, requiredMetrics, nil)
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("expected text/plain Content-Type, got %s", rec.Header().Get("Content-Type"))
	}
}
