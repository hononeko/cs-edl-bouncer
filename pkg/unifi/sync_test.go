package unifi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

type mockUniFiState struct {
	mu            sync.Mutex
	zones         []Zone
	groups        map[string]FirewallGroup
	policies      map[string]FirewallZonePolicy
	createdGroups int
	updatedGroups int
	deletedGroups int
	createdPols   int
	updatedPols   int
	deletedPols   int
	reorderCalls  int
}

func newMockUniFiServer(state *mockUniFiState) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")

		// 1. Zones
		if r.Method == http.MethodGet && r.URL.Path == "/proxy/network/v2/api/site/default/firewall/zone" {
			_ = json.NewEncoder(w).Encode(state.zones)
			return
		}

		// 2. Groups
		if r.Method == http.MethodGet && r.URL.Path == "/proxy/network/api/s/default/rest/firewallgroup" {
			list := make([]FirewallGroup, 0, len(state.groups))
			for _, g := range state.groups {
				list = append(list, g)
			}
			_ = json.NewEncoder(w).Encode(unifiResponse[FirewallGroup]{Data: list})
			return
		}

		if r.Method == http.MethodPost && r.URL.Path == "/proxy/network/api/s/default/rest/firewallgroup" {
			var g FirewallGroup
			_ = json.NewDecoder(r.Body).Decode(&g)
			state.createdGroups++
			g.ID = fmt.Sprintf("grp-%d", state.createdGroups)
			state.groups[g.ID] = g
			_ = json.NewEncoder(w).Encode(unifiResponse[FirewallGroup]{Data: []FirewallGroup{g}})
			return
		}

		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/proxy/network/api/s/default/rest/firewallgroup/") {
			id := strings.TrimPrefix(r.URL.Path, "/proxy/network/api/s/default/rest/firewallgroup/")
			var g FirewallGroup
			_ = json.NewDecoder(r.Body).Decode(&g)
			state.updatedGroups++
			g.ID = id
			state.groups[id] = g
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/proxy/network/api/s/default/rest/firewallgroup/") {
			id := strings.TrimPrefix(r.URL.Path, "/proxy/network/api/s/default/rest/firewallgroup/")
			state.deletedGroups++
			delete(state.groups, id)
			w.WriteHeader(http.StatusOK)
			return
		}

		// 3. Policies
		if r.Method == http.MethodGet && r.URL.Path == "/proxy/network/v2/api/site/default/firewall-policies" {
			list := make([]FirewallZonePolicy, 0, len(state.policies))
			for _, p := range state.policies {
				list = append(list, p)
			}
			_ = json.NewEncoder(w).Encode(list)
			return
		}

		if r.Method == http.MethodPost && r.URL.Path == "/proxy/network/v2/api/site/default/firewall-policies" {
			var p FirewallZonePolicy
			_ = json.NewDecoder(r.Body).Decode(&p)
			state.createdPols++
			p.ID = fmt.Sprintf("pol-%d", state.createdPols)
			p.Index = 10000 + len(state.policies)
			state.policies[p.ID] = p
			_ = json.NewEncoder(w).Encode(p)
			return
		}

		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/proxy/network/v2/api/site/default/firewall-policies/batch-reorder") {
			var req BatchReorderRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			state.reorderCalls++
			for idx, id := range req.BeforePredefinedIDs {
				if pol, ok := state.policies[id]; ok {
					pol.Index = 10000 + idx
					state.policies[id] = pol
				}
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/proxy/network/v2/api/site/default/firewall-policies/") {
			id := strings.TrimPrefix(r.URL.Path, "/proxy/network/v2/api/site/default/firewall-policies/")
			var p FirewallZonePolicy
			_ = json.NewDecoder(r.Body).Decode(&p)
			state.updatedPols++
			p.ID = id
			state.policies[id] = p
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/proxy/network/v2/api/site/default/firewall-policies/") {
			id := strings.TrimPrefix(r.URL.Path, "/proxy/network/v2/api/site/default/firewall-policies/")
			state.deletedPols++
			delete(state.policies, id)
			w.WriteHeader(http.StatusOK)
			return
		}

		http.NotFound(w, r)
	}))
}

func TestBuildTargetShards(t *testing.T) {
	shards := buildTargetShards("https://lists.lan", 2, 1)
	if len(shards) != 3 {
		t.Fatalf("expected 3 shards, got %d", len(shards))
	}

	if shards[0].Name != "CrowdSec-EDL-IPv4-0" || shards[0].URL != "https://lists.lan/ipv4-0.txt" || shards[0].IPVersion != "IPV4" {
		t.Errorf("unexpected shard[0]: %+v", shards[0])
	}
	if shards[1].Name != "CrowdSec-EDL-IPv4-1" || shards[1].URL != "https://lists.lan/ipv4-1.txt" || shards[1].IPVersion != "IPV4" {
		t.Errorf("unexpected shard[1]: %+v", shards[1])
	}
	if shards[2].Name != "CrowdSec-EDL-IPv6-0" || shards[2].URL != "https://lists.lan/ipv6-0.txt" || shards[2].IPVersion != "IPV6" {
		t.Errorf("unexpected shard[2]: %+v", shards[2])
	}
}

func newTestState() *mockUniFiState {
	return &mockUniFiState{
		zones: []Zone{
			{ID: "zone-ext", Name: "External"},
			{ID: "zone-int", Name: "Internal"},
		},
		groups:   make(map[string]FirewallGroup),
		policies: make(map[string]FirewallZonePolicy),
	}
}

func newTestConfig(serverURL string, ipv4Shards, ipv6Shards int) *Config {
	return &Config{
		Host:               serverURL,
		APIKey:             "test-key",
		Site:               "default",
		SkipTLSVerify:      true,
		ZoneSrc:            []string{"External"},
		ZoneDst:            []string{"Internal"},
		BaseURL:            "https://blocklist.test/lists",
		IPv4Shards:         ipv4Shards,
		IPv6Shards:         ipv6Shards,
		UpdateIntervalSecs: 3600,
		RuleAction:         "BLOCK",
		RuleStates:         []string{"NEW", "INVALID"},
		PruneLegacy:        false,
	}
}

func TestReconcileCreationAndIdempotency(t *testing.T) {
	state := newTestState()
	server := newMockUniFiServer(state)
	defer server.Close()

	cfg := newTestConfig(server.URL, 2, 1)
	client := NewClient(cfg, nil)
	ctx := context.Background()

	// 1. Initial reconciliation: should create 3 groups and 3 policies
	if err := Reconcile(ctx, client, cfg); err != nil {
		t.Fatalf("initial Reconcile failed: %v", err)
	}

	if state.createdGroups != 3 {
		t.Errorf("expected 3 groups created, got %d", state.createdGroups)
	}
	if state.createdPols != 3 {
		t.Errorf("expected 3 policies created, got %d", state.createdPols)
	}

	// 2. Second reconciliation: should be completely idempotent (0 creates, 0 updates)
	state.createdGroups = 0
	state.createdPols = 0
	state.updatedGroups = 0
	state.updatedPols = 0
	state.reorderCalls = 0

	if err := Reconcile(ctx, client, cfg); err != nil {
		t.Fatalf("second Reconcile failed: %v", err)
	}

	if state.createdGroups != 0 {
		t.Errorf("expected 0 groups created on re-run, got %d", state.createdGroups)
	}
	if state.createdPols != 0 {
		t.Errorf("expected 0 policies created on re-run, got %d", state.createdPols)
	}
	if state.updatedGroups != 0 {
		t.Errorf("expected 0 groups updated on re-run, got %d", state.updatedGroups)
	}
	if state.updatedPols != 0 {
		t.Errorf("expected 0 policies updated on re-run, got %d", state.updatedPols)
	}
}

func TestReconcileDriftHealing(t *testing.T) {
	state := newTestState()
	server := newMockUniFiServer(state)
	defer server.Close()

	cfg := newTestConfig(server.URL, 1, 0)
	client := NewClient(cfg, nil)
	ctx := context.Background()

	// Initial sync
	if err := Reconcile(ctx, client, cfg); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Introduce group drift: change interval in state
	for k, g := range state.groups {
		g.UpdateIntervalSeconds = 1800
		state.groups[k] = g
	}

	// Introduce policy drift: change rule state in state
	for k, p := range state.policies {
		p.ConnectionStates = []string{"NEW"}
		state.policies[k] = p
	}

	state.updatedGroups = 0
	state.updatedPols = 0

	if err := Reconcile(ctx, client, cfg); err != nil {
		t.Fatalf("Reconcile drift healing failed: %v", err)
	}

	if state.updatedGroups != 1 {
		t.Errorf("expected 1 group updated, got %d", state.updatedGroups)
	}
	if state.updatedPols != 1 {
		t.Errorf("expected 1 policy updated, got %d", state.updatedPols)
	}
}

func TestReconcileLegacyPruning(t *testing.T) {
	state := newTestState()
	state.groups["legacy-grp"] = FirewallGroup{
		ID:   "legacy-grp",
		Name: "cs-unifi-bouncer-ipv4",
	}
	state.policies["legacy-pol"] = FirewallZonePolicy{
		ID:   "legacy-pol",
		Name: "cs-unifi-bouncer-rule",
	}
	state.policies["legacy-static"] = FirewallZonePolicy{
		ID:   "797c809c-5e49-4a4b-9952-e3db1c462dd0",
		Name: "Block CrowdSec Reported Threats",
	}

	server := newMockUniFiServer(state)
	defer server.Close()

	cfg := newTestConfig(server.URL, 1, 0)
	cfg.PruneLegacy = true

	client := NewClient(cfg, nil)
	ctx := context.Background()

	if err := Reconcile(ctx, client, cfg); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	if state.deletedGroups != 1 {
		t.Errorf("expected 1 legacy group deleted, got %d", state.deletedGroups)
	}
	if state.deletedPols != 2 {
		t.Errorf("expected 2 legacy policies deleted, got %d", state.deletedPols)
	}
}

func TestReconcileMissingZones(t *testing.T) {
	state := &mockUniFiState{
		zones:    []Zone{{ID: "zone-ext", Name: "External"}},
		groups:   make(map[string]FirewallGroup),
		policies: make(map[string]FirewallZonePolicy),
	}

	server := newMockUniFiServer(state)
	defer server.Close()

	cfg := newTestConfig(server.URL, 1, 0)
	cfg.ZoneDst = []string{"NonExistentZone"}

	client := NewClient(cfg, nil)
	err := Reconcile(context.Background(), client, cfg)
	if err == nil {
		t.Fatal("expected error when destination zone not found, got nil")
	}
	if !strings.Contains(err.Error(), "no matching source or destination zones resolved") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRunSync(t *testing.T) {
	state := newTestState()
	server := newMockUniFiServer(state)
	defer server.Close()

	_ = os.Setenv("UNIFI_HOST", server.URL)
	_ = os.Setenv("UNIFI_API_KEY", "test-api-key")
	_ = os.Setenv("UNIFI_SITE", "default")
	_ = os.Setenv("UNIFI_ZONE_SRC", "External")
	_ = os.Setenv("UNIFI_ZONE_DST", "Internal")
	_ = os.Setenv("EDL_IPV4_SHARDS", "1")
	_ = os.Setenv("EDL_IPV6_SHARDS", "0")
	defer func() {
		_ = os.Unsetenv("UNIFI_HOST")
		_ = os.Unsetenv("UNIFI_API_KEY")
		_ = os.Unsetenv("UNIFI_SITE")
		_ = os.Unsetenv("UNIFI_ZONE_SRC")
		_ = os.Unsetenv("UNIFI_ZONE_DST")
		_ = os.Unsetenv("EDL_IPV4_SHARDS")
		_ = os.Unsetenv("EDL_IPV6_SHARDS")
	}()

	if err := RunSync(context.Background()); err != nil {
		t.Fatalf("RunSync failed: %v", err)
	}
	if state.createdGroups != 1 {
		t.Errorf("expected 1 group created, got %d", state.createdGroups)
	}
}

func TestPolicyDrifted(t *testing.T) {
	base := &FirewallZonePolicy{
		Action:             "BLOCK",
		Enabled:            true,
		CreateAllowRespond: false,
		ConnectionStates:   []string{"NEW", "INVALID"},
		Source: FirewallZonePolicySource{
			IPGroupID: "grp-1",
		},
	}

	// Identical
	curr := *base
	if policyDrifted(&curr, base, "grp-1") {
		t.Error("expected no drift for identical policy")
	}

	// Action changed
	curr = *base
	curr.Action = "ACCEPT"
	if !policyDrifted(&curr, base, "grp-1") {
		t.Error("expected drift when action changed")
	}

	// Disabled
	curr = *base
	curr.Enabled = false
	if !policyDrifted(&curr, base, "grp-1") {
		t.Error("expected drift when disabled")
	}

	// CreateAllowRespond is true
	curr = *base
	curr.CreateAllowRespond = true
	if !policyDrifted(&curr, base, "grp-1") {
		t.Error("expected drift when CreateAllowRespond is true")
	}

	// IPGroupID changed
	curr = *base
	if !policyDrifted(&curr, base, "grp-other") {
		t.Error("expected drift when IPGroupID changed")
	}

	// ConnectionStates changed
	curr = *base
	curr.ConnectionStates = []string{"NEW"}
	if !policyDrifted(&curr, base, "grp-1") {
		t.Error("expected drift when ConnectionStates changed")
	}
}

func TestIndexOfSuffix(t *testing.T) {
	patterns := []string{"ipv4-External->Internal-0", "ipv4-External->Internal-1"}
	if idx := indexOfSuffix("CrowdSec-EDL-ipv4-External->Internal-0", patterns); idx != 0 {
		t.Errorf("expected idx 0, got %d", idx)
	}
	if idx := indexOfSuffix("CrowdSec-EDL-ipv4-External->Internal-1", patterns); idx != 1 {
		t.Errorf("expected idx 1, got %d", idx)
	}
	if idx := indexOfSuffix("Some-Other-Rule", patterns); idx != 999 {
		t.Errorf("expected idx 999 for non-matching, got %d", idx)
	}
}
