package crowdsec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v1/decisions/stream" {
			t.Errorf("expected /v1/decisions/stream, got %s", r.URL.Path)
		}
		if r.Header.Get("X-Api-Key") != "secret-api-key" {
			t.Errorf("expected X-Api-Key secret-api-key, got %s", r.Header.Get("X-Api-Key"))
		}
		if r.Header.Get("User-Agent") != "cs-edl-bouncer/1.0.0" {
			t.Errorf("expected User-Agent cs-edl-bouncer/1.0.0, got %s", r.Header.Get("User-Agent"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("expected Accept application/json, got %s", r.Header.Get("Accept"))
		}

		q := r.URL.Query()
		if q.Get("startup") != "true" {
			t.Errorf("expected startup=true, got %s", q.Get("startup"))
		}
		if q.Get("scopes") != "ip,range" {
			t.Errorf("expected scopes=ip,range, got %s", q.Get("scopes"))
		}
		if q.Get("origins") != "crowdsec,lists" {
			t.Errorf("expected origins=crowdsec,lists, got %s", q.Get("origins"))
		}

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
