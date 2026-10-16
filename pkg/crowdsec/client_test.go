package crowdsec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func assertStreamRequest(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Method != http.MethodGet {
		t.Errorf("expected GET, got %s", r.Method)
	}
	if r.URL.Path != "/v1/decisions/stream" {
		t.Errorf("expected /v1/decisions/stream, got %s", r.URL.Path)
	}

	expectedHeaders := map[string]string{
		"X-Api-Key":  "secret-api-key",
		"User-Agent": "cs-edl-bouncer/1.0.0",
		"Accept":     "application/json",
	}
	for k, v := range expectedHeaders {
		if got := r.Header.Get(k); got != v {
			t.Errorf("expected header %s=%s, got %s", k, v, got)
		}
	}

	q := r.URL.Query()
	expectedQuery := map[string]string{
		"startup": "true",
		"scopes":  "ip,range",
		"origins": "crowdsec,lists",
	}
	for k, v := range expectedQuery {
		if got := q.Get(k); got != v {
			t.Errorf("expected query %s=%s, got %s", k, v, got)
		}
	}
}

func TestGetStreamSuccess(t *testing.T) {
	expectedNew := []Decision{
		{
			ID:       101,
			Origin:   "crowdsec",
			Type:     "ban",
			Scope:    "ip",
			Value:    "1.2.3.4",
			Duration: "4h",
			Scenario: "crowdsecurity/ssh-bf",
		},
	}
	expectedDel := []Decision{
		{
			ID:    100,
			Value: "5.6.7.8",
			Type:  "ban",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertStreamRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(StreamResponse{
			New:     expectedNew,
			Deleted: expectedDel,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "secret-api-key", []string{"crowdsec", "lists"}, server.Client())
	resp, err := client.GetStream(context.Background(), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.New) != 1 || resp.New[0].ID != 101 || resp.New[0].Value != "1.2.3.4" {
		t.Errorf("unexpected New decisions: %+v", resp.New)
	}
	if len(resp.Deleted) != 1 || resp.Deleted[0].ID != 100 || resp.Deleted[0].Value != "5.6.7.8" {
		t.Errorf("unexpected Deleted decisions: %+v", resp.Deleted)
	}
}

func TestGetStreamErrors(t *testing.T) {
	t.Run("server error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unauthorized access", http.StatusUnauthorized)
		}))
		defer server.Close()

		client := NewClient(server.URL, "wrong-key", nil, server.Client())
		_, err := client.GetStream(context.Background(), false)
		if err == nil {
			t.Fatalf("expected error on 401, got nil")
		}
		if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "unauthorized") {
			t.Errorf("expected 401 unauthorized in error, got %v", err)
		}
	})

	t.Run("invalid json response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not json"))
		}))
		defer server.Close()

		client := NewClient(server.URL, "key", nil, server.Client())
		_, err := client.GetStream(context.Background(), false)
		if err == nil {
			t.Fatalf("expected JSON decode error, got nil")
		}
	})

	t.Run("network error", func(t *testing.T) {
		client := NewClient("http://127.0.0.1:59999", "key", nil, nil)
		_, err := client.GetStream(context.Background(), false)
		if err == nil {
			t.Fatalf("expected network error, got nil")
		}
	})
}
