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
	st := store.NewStore([]string{"ban"}, 9500, 3, 1, true)
	st.ProcessStream(true, &crowdsec.StreamResponse{
		New: []crowdsec.Decision{
			{ID: 1, Type: "ban", Value: "10.0.0.1"},
			{ID: 2, Type: "ban", Value: "2001:db8::1"},
		},
	})
	return New(st)
}

func TestHealthEndpoints(t *testing.T) {
	srv := setupTestServer()
	handler := srv.Handler()

	paths := []string{"/healthz", "/readyz", "/"}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s returned status %d, expected 200", p, rec.Code)
		}
	}
}

func TestListsEndpoint(t *testing.T) {
	srv := setupTestServer()
	handler := srv.Handler()

	t.Run("serve existing shard", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/lists/ipv4-0.txt", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "10.0.0.1") {
			t.Errorf("expected 10.0.0.1 in response, got %s", rec.Body.String())
		}
		if !strings.Contains(rec.Header().Get("Content-Type"), "text/plain") {
			t.Errorf("expected text/plain Content-Type, got %s", rec.Header().Get("Content-Type"))
		}
	})

	t.Run("serve combined list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/lists/all.txt", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "10.0.0.1") || !strings.Contains(body, "2001:db8::1") {
			t.Errorf("expected both IPs in all.txt, got %s", body)
		}
	})

	t.Run("unknown shard returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/lists/nonexistent.txt", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rec.Code)
		}
	})

	t.Run("path traversal attempt returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/lists/..%2fpasswd", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 404 or 400 for path traversal, got %d", rec.Code)
		}
	})
}

func TestSecurityBlocklistEndpoint(t *testing.T) {
	srv := setupTestServer()
	handler := srv.Handler()

	t.Run("default serves all.txt", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/security/blocklist.txt", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "10.0.0.1") || !strings.Contains(body, "2001:db8::1") {
			t.Errorf("expected both IPs in blocklist.txt, got %s", body)
		}
	})

	t.Run("ipv4only param serves ipv4.txt", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/security/blocklist.txt?ipv4only", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "10.0.0.1") || strings.Contains(body, "2001:db8::1") {
			t.Errorf("expected only IPv4 in blocklist.txt?ipv4only, got %s", body)
		}
	})

	t.Run("ipv6only param serves ipv6.txt", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/security/blocklist.txt?ipv6only", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		body := rec.Body.String()
		if strings.Contains(body, "10.0.0.1") || !strings.Contains(body, "2001:db8::1") {
			t.Errorf("expected only IPv6 in blocklist.txt?ipv6only, got %s", body)
		}
	})
}

func TestMetricsEndpoint(t *testing.T) {
	srv := setupTestServer()
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()

	requiredMetrics := []string{
		"cs_edl_decisions_raw 2",
		"cs_edl_entries_ipv4 1",
		"cs_edl_entries_ipv6 1",
		"cs_edl_shards_ipv4 3",
		"cs_edl_shards_ipv6 1",
		"cs_edl_sync_success_total 1",
		"cs_edl_sync_failure_total 0",
		"cs_edl_last_sync_timestamp_seconds",
	}

	for _, metric := range requiredMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("expected metric %q in /metrics output:\n%s", metric, body)
		}
	}
}
