package unifi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestClientEndpoints(t *testing.T) {
	var checkedAPIKey atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != "secret-test-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		checkedAPIKey.Store(true)

		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/proxy/network/v2/api/site/default/firewall/zone":
			_ = json.NewEncoder(w).Encode([]Zone{
				{ID: "zone-ext", Name: "External"},
				{ID: "zone-int", Name: "Internal"},
			})

		case r.Method == http.MethodGet && r.URL.Path == "/proxy/network/api/s/default/rest/firewallgroup":
			_ = json.NewEncoder(w).Encode(unifiResponse[FirewallGroup]{
				Data: []FirewallGroup{
					{ID: "grp-1", Name: "CrowdSec-EDL-IPv4-0", GroupType: "address-group", URL: "http://example.com/0.txt"},
				},
			})

		case r.Method == http.MethodPost && r.URL.Path == "/proxy/network/api/s/default/rest/firewallgroup":
			var g FirewallGroup
			if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			g.ID = "new-grp-id"
			_ = json.NewEncoder(w).Encode(unifiResponse[FirewallGroup]{
				Data: []FirewallGroup{g},
			})

		case r.Method == http.MethodPut && r.URL.Path == "/proxy/network/api/s/default/rest/firewallgroup/grp-1":
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodDelete && r.URL.Path == "/proxy/network/api/s/default/rest/firewallgroup/grp-1":
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodGet && r.URL.Path == "/proxy/network/v2/api/site/default/firewall-policies":
			_ = json.NewEncoder(w).Encode([]FirewallZonePolicy{
				{ID: "pol-1", Name: "CrowdSec-EDL-ipv4-External->Internal-0", Action: "BLOCK"},
			})

		case r.Method == http.MethodPost && r.URL.Path == "/proxy/network/v2/api/site/default/firewall-policies":
			var p FirewallZonePolicy
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			p.ID = "new-pol-id"
			_ = json.NewEncoder(w).Encode(p)

		case r.Method == http.MethodPut && r.URL.Path == "/proxy/network/v2/api/site/default/firewall-policies/pol-1":
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodDelete && r.URL.Path == "/proxy/network/v2/api/site/default/firewall-policies/pol-1":
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodPut && r.URL.Path == "/proxy/network/v2/api/site/default/firewall-policies/batch-reorder":
			w.WriteHeader(http.StatusOK)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := &Config{
		Host:          server.URL,
		APIKey:        "secret-test-key",
		Site:          "default",
		SkipTLSVerify: true,
	}

	client := NewClient(cfg, nil)
	ctx := context.Background()

	// 1. ListZones
	zones, err := client.ListZones(ctx)
	if err != nil {
		t.Fatalf("ListZones failed: %v", err)
	}
	if len(zones) != 2 || zones[0].Name != "External" {
		t.Errorf("unexpected zones: %v", zones)
	}

	// 2. ListGroups
	groups, err := client.ListGroups(ctx)
	if err != nil {
		t.Fatalf("ListGroups failed: %v", err)
	}
	if len(groups) != 1 || groups[0].ID != "grp-1" {
		t.Errorf("unexpected groups: %v", groups)
	}

	// 3. CreateGroup
	createdGrp, err := client.CreateGroup(ctx, &FirewallGroup{
		Name:      "NewGroup",
		GroupType: "address-group",
	})
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}
	if createdGrp.ID != "new-grp-id" {
		t.Errorf("expected created group ID 'new-grp-id', got %q", createdGrp.ID)
	}

	// 4. UpdateGroup
	if err := client.UpdateGroup(ctx, "grp-1", &FirewallGroup{Name: "Updated"}); err != nil {
		t.Fatalf("UpdateGroup failed: %v", err)
	}

	// 5. DeleteGroup
	if err := client.DeleteGroup(ctx, "grp-1"); err != nil {
		t.Fatalf("DeleteGroup failed: %v", err)
	}

	// 6. ListPolicies
	policies, err := client.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies failed: %v", err)
	}
	if len(policies) != 1 || policies[0].ID != "pol-1" {
		t.Errorf("unexpected policies: %v", policies)
	}

	// 7. CreatePolicy
	createdPol, err := client.CreatePolicy(ctx, &FirewallZonePolicy{
		Name:   "NewPolicy",
		Action: "BLOCK",
	})
	if err != nil {
		t.Fatalf("CreatePolicy failed: %v", err)
	}
	if createdPol.ID != "new-pol-id" {
		t.Errorf("expected created policy ID 'new-pol-id', got %q", createdPol.ID)
	}

	// 8. UpdatePolicy
	if err := client.UpdatePolicy(ctx, "pol-1", &FirewallZonePolicy{Name: "Updated"}); err != nil {
		t.Fatalf("UpdatePolicy failed: %v", err)
	}

	// 9. DeletePolicy
	if err := client.DeletePolicy(ctx, "pol-1"); err != nil {
		t.Fatalf("DeletePolicy failed: %v", err)
	}

	// 10. BatchReorder
	if err := client.BatchReorder(ctx, &BatchReorderRequest{
		SourceZoneID:        "zone-ext",
		DestinationZoneID:   "zone-int",
		BeforePredefinedIDs: []string{"new-pol-id"},
	}); err != nil {
		t.Fatalf("BatchReorder failed: %v", err)
	}

	if !checkedAPIKey.Load() {
		t.Error("expected X-API-KEY header to be verified")
	}
}

func TestClientRetries(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		att := attempts.Add(1)
		if att == 1 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("502 Bad Gateway"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]Zone{{ID: "z1", Name: "External"}})
	}))
	defer server.Close()

	cfg := &Config{
		Host:   server.URL,
		APIKey: "key",
		Site:   "default",
	}

	client := NewClient(cfg, nil)
	zones, err := client.ListZones(context.Background())
	if err != nil {
		t.Fatalf("expected retry to succeed, got error: %v", err)
	}
	if len(zones) != 1 {
		t.Errorf("expected 1 zone, got %d", len(zones))
	}
	if attempts.Load() != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts.Load())
	}
}

func TestClientErrors(t *testing.T) {
	t.Run("non_retryable_400", func(t *testing.T) {
		var attempts atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts.Add(1)
			http.Error(w, "bad request parameter", http.StatusBadRequest)
		}))
		defer server.Close()

		client := NewClient(&Config{Host: server.URL, APIKey: "key", Site: "default"}, nil)
		_, err := client.ListZones(context.Background())
		if err == nil {
			t.Fatal("expected error on 400, got nil")
		}
		if attempts.Load() != 1 {
			t.Errorf("expected 1 attempt (no retry on 400), got %d", attempts.Load())
		}
	})

	t.Run("empty_group_response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(unifiResponse[FirewallGroup]{Data: []FirewallGroup{}})
		}))
		defer server.Close()

		client := NewClient(&Config{Host: server.URL, APIKey: "key", Site: "default"}, nil)
		_, err := client.CreateGroup(context.Background(), &FirewallGroup{Name: "G"})
		if err == nil {
			t.Fatal("expected error on empty response, got nil")
		}
	})
}
