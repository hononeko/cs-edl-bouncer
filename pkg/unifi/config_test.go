package unifi

import (
	"os"
	"slices"
	"testing"
)

func TestLoadConfigDefaults(t *testing.T) {
	env := map[string]string{
		"UNIFI_API_KEY": "test-key-123",
	}

	cfg, err := LoadConfigFromEnv(func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Host != "https://10.10.1.1" {
		t.Errorf("expected default host https://10.10.1.1, got %q", cfg.Host)
	}
	if cfg.Site != "default" {
		t.Errorf("expected default site default, got %q", cfg.Site)
	}
	if !cfg.SkipTLSVerify {
		t.Errorf("expected default SkipTLSVerify true, got false")
	}
	if !slices.Equal(cfg.ZoneSrc, []string{"External"}) {
		t.Errorf("expected default ZoneSrc [External], got %v", cfg.ZoneSrc)
	}
	expectedDst := []string{"Internal", "Gateway", "Vpn", "Hotspot", "Dmz", "IoT", "HomeLab"}
	if !slices.Equal(cfg.ZoneDst, expectedDst) {
		t.Errorf("expected default ZoneDst %v, got %v", expectedDst, cfg.ZoneDst)
	}
	if cfg.BaseURL != "https://blocklist.kerrlab.app/lists" {
		t.Errorf("expected default BaseURL https://blocklist.kerrlab.app/lists, got %q", cfg.BaseURL)
	}
	if cfg.IPv4Shards != 3 {
		t.Errorf("expected IPv4Shards=3, got %d", cfg.IPv4Shards)
	}
	if cfg.IPv6Shards != 1 {
		t.Errorf("expected IPv6Shards=1, got %d", cfg.IPv6Shards)
	}
	if cfg.UpdateIntervalSecs != 3600 {
		t.Errorf("expected UpdateIntervalSecs=3600, got %d", cfg.UpdateIntervalSecs)
	}
	if cfg.RuleAction != "BLOCK" {
		t.Errorf("expected RuleAction=BLOCK, got %q", cfg.RuleAction)
	}
	if !slices.Equal(cfg.RuleStates, []string{"NEW", "INVALID"}) {
		t.Errorf("expected RuleStates [NEW, INVALID], got %v", cfg.RuleStates)
	}
	if cfg.PruneLegacy {
		t.Errorf("expected PruneLegacy=false, got true")
	}
}

func TestMissingAPIKey(t *testing.T) {
	_, err := LoadConfigFromEnv(func(string) (string, bool) {
		return "", false
	})
	if err == nil {
		t.Fatal("expected error when UNIFI_API_KEY is missing, got nil")
	}
	if err.Error() != "UNIFI_API_KEY is required" {
		t.Errorf("expected error message 'UNIFI_API_KEY is required', got %q", err.Error())
	}
}

func TestCustomEnvironment(t *testing.T) {
	env := map[string]string{
		"UNIFI_HOST":                  "https://unifi.lan:8443/",
		"UNIFI_API_KEY":               "custom-secret",
		"UNIFI_SITE":                  "custom-site",
		"UNIFI_SKIP_TLS_VERIFY":       "false",
		"UNIFI_ZONE_SRC":              "External, Wan",
		"UNIFI_ZONE_DST":              "Internal, Guest, DMZ",
		"EDL_BASE_URL":                "http://edl.local:8080/lists/",
		"EDL_IPV4_SHARDS":             "5",
		"EDL_IPV6_SHARDS":             "2",
		"EDL_UPDATE_INTERVAL_SECONDS": "7200",
		"EDL_RULE_ACTION":             "drop",
		"EDL_RULE_STATES":             "new, established, related",
		"PRUNE_LEGACY":                "true",
	}

	cfg, err := LoadConfigFromEnv(func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Host != "https://unifi.lan:8443" {
		t.Errorf("expected trailing slash removed from Host, got %q", cfg.Host)
	}
	if cfg.BaseURL != "http://edl.local:8080/lists" {
		t.Errorf("expected trailing slash removed from BaseURL, got %q", cfg.BaseURL)
	}
	if cfg.Site != "custom-site" {
		t.Errorf("expected Site=custom-site, got %q", cfg.Site)
	}
	if cfg.SkipTLSVerify {
		t.Errorf("expected SkipTLSVerify=false, got true")
	}
	if !slices.Equal(cfg.ZoneSrc, []string{"External", "Wan"}) {
		t.Errorf("expected ZoneSrc [External, Wan], got %v", cfg.ZoneSrc)
	}
	if !slices.Equal(cfg.ZoneDst, []string{"Internal", "Guest", "DMZ"}) {
		t.Errorf("expected ZoneDst [Internal, Guest, DMZ], got %v", cfg.ZoneDst)
	}
	if cfg.IPv4Shards != 5 {
		t.Errorf("expected IPv4Shards=5, got %d", cfg.IPv4Shards)
	}
	if cfg.IPv6Shards != 2 {
		t.Errorf("expected IPv6Shards=2, got %d", cfg.IPv6Shards)
	}
	if cfg.UpdateIntervalSecs != 7200 {
		t.Errorf("expected UpdateIntervalSecs=7200, got %d", cfg.UpdateIntervalSecs)
	}
	if cfg.RuleAction != "DROP" {
		t.Errorf("expected RuleAction=DROP, got %q", cfg.RuleAction)
	}
	if !slices.Equal(cfg.RuleStates, []string{"NEW", "ESTABLISHED", "RELATED"}) {
		t.Errorf("expected uppercase RuleStates, got %v", cfg.RuleStates)
	}
	if !cfg.PruneLegacy {
		t.Errorf("expected PruneLegacy=true, got false")
	}
}

func TestInvalidConfigurations(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "invalid_tls_verify_bool",
			env:  map[string]string{"UNIFI_API_KEY": "k", "UNIFI_SKIP_TLS_VERIFY": "not-bool"},
		},
		{
			name: "invalid_ipv4_shards_text",
			env:  map[string]string{"UNIFI_API_KEY": "k", "EDL_IPV4_SHARDS": "abc"},
		},
		{
			name: "zero_ipv4_shards",
			env:  map[string]string{"UNIFI_API_KEY": "k", "EDL_IPV4_SHARDS": "0"},
		},
		{
			name: "negative_ipv6_shards",
			env:  map[string]string{"UNIFI_API_KEY": "k", "EDL_IPV6_SHARDS": "-1"},
		},
		{
			name: "invalid_interval_text",
			env:  map[string]string{"UNIFI_API_KEY": "k", "EDL_UPDATE_INTERVAL_SECONDS": "xyz"},
		},
		{
			name: "too_short_interval",
			env:  map[string]string{"UNIFI_API_KEY": "k", "EDL_UPDATE_INTERVAL_SECONDS": "59"},
		},
		{
			name: "invalid_prune_legacy_bool",
			env:  map[string]string{"UNIFI_API_KEY": "k", "PRUNE_LEGACY": "invalid"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadConfigFromEnv(func(k string) (string, bool) {
				v, ok := tc.env[k]
				return v, ok
			})
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestLoadConfigWithOSEnv(t *testing.T) {
	_ = os.Setenv("UNIFI_API_KEY", "env-test-key")
	defer func() {
		_ = os.Unsetenv("UNIFI_API_KEY")
	}()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() failed: %v", err)
	}
	if cfg.APIKey != "env-test-key" {
		t.Errorf("expected APIKey=env-test-key, got %q", cfg.APIKey)
	}
}
