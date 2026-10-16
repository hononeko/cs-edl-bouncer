package config

import (
	"os"
	"reflect"
	"testing"
	"time"
)

func mockLookup(env map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		val, ok := env[key]
		return val, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	env := map[string]string{
		"CROWDSEC_API_KEY": "test-key-123",
	}

	cfg, err := LoadFromEnv(mockLookup(env))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.CrowdSecURL != "http://crowdsec-service:8080" {
		t.Errorf("expected default CrowdSecURL, got %q", cfg.CrowdSecURL)
	}
	if cfg.APIKey != "test-key-123" {
		t.Errorf("expected APIKey test-key-123, got %q", cfg.APIKey)
	}
	if cfg.UpdateInterval != 30*time.Second {
		t.Errorf("expected default UpdateInterval 30s, got %v", cfg.UpdateInterval)
	}
	if !reflect.DeepEqual(cfg.DecisionTypes, []string{"ban"}) {
		t.Errorf("expected default DecisionTypes [ban], got %v", cfg.DecisionTypes)
	}
	if len(cfg.Origins) != 0 {
		t.Errorf("expected empty Origins, got %v", cfg.Origins)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("expected default ListenAddr :8080, got %q", cfg.ListenAddr)
	}
	if cfg.ShardSize != 9500 {
		t.Errorf("expected default ShardSize 9500, got %d", cfg.ShardSize)
	}
	if cfg.MinIPv4Shards != 3 {
		t.Errorf("expected default MinIPv4Shards 3, got %d", cfg.MinIPv4Shards)
	}
	if cfg.MinIPv6Shards != 1 {
		t.Errorf("expected default MinIPv6Shards 1, got %d", cfg.MinIPv6Shards)
	}
	if !cfg.AggregateCIDR {
		t.Errorf("expected default AggregateCIDR true, got false")
	}
}

func TestAPIKeyFallback(t *testing.T) {
	env := map[string]string{
		"BOUNCER_API_KEY": "fallback-key",
	}

	cfg, err := LoadFromEnv(mockLookup(env))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIKey != "fallback-key" {
		t.Errorf("expected APIKey fallback-key, got %q", cfg.APIKey)
	}
}

func TestMissingAPIKey(t *testing.T) {
	env := map[string]string{}
	_, err := LoadFromEnv(mockLookup(env))
	if err == nil {
		t.Fatalf("expected error when API key is missing, got nil")
	}
}

func TestCustomConfiguration(t *testing.T) {
	env := map[string]string{
		"CROWDSEC_API_KEY":         "my-key",
		"CROWDSEC_URL":             "https://crowdsec.internal:8443/",
		"CROWDSEC_UPDATE_INTERVAL": "45s",
		"CROWDSEC_ORIGINS":         "crowdsec, cscli CAPI,lists",
		"CROWDSEC_DECISION_TYPES":  "BAN, captcha",
		"LISTEN_ADDR":              "0.0.0.0:9090",
		"EDL_SHARD_SIZE":           "5000",
		"EDL_MIN_IPV4_SHARDS":      "5",
		"EDL_MIN_IPV6_SHARDS":      "2",
		"EDL_AGGREGATE_CIDR":       "false",
	}

	cfg, err := LoadFromEnv(mockLookup(env))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.CrowdSecURL != "https://crowdsec.internal:8443" {
		t.Errorf("expected CrowdSecURL trimmed trailing slash, got %q", cfg.CrowdSecURL)
	}
	if cfg.UpdateInterval != 45*time.Second {
		t.Errorf("expected UpdateInterval 45s, got %v", cfg.UpdateInterval)
	}
	expectedOrigins := []string{"crowdsec", "cscli", "CAPI", "lists"}
	if !reflect.DeepEqual(cfg.Origins, expectedOrigins) {
		t.Errorf("expected Origins %v, got %v", expectedOrigins, cfg.Origins)
	}
	expectedTypes := []string{"ban", "captcha"}
	if !reflect.DeepEqual(cfg.DecisionTypes, expectedTypes) {
		t.Errorf("expected DecisionTypes %v, got %v", expectedTypes, cfg.DecisionTypes)
	}
	if cfg.ListenAddr != "0.0.0.0:9090" {
		t.Errorf("expected ListenAddr 0.0.0.0:9090, got %q", cfg.ListenAddr)
	}
	if cfg.ShardSize != 5000 {
		t.Errorf("expected ShardSize 5000, got %d", cfg.ShardSize)
	}
	if cfg.MinIPv4Shards != 5 {
		t.Errorf("expected MinIPv4Shards 5, got %d", cfg.MinIPv4Shards)
	}
	if cfg.MinIPv6Shards != 2 {
		t.Errorf("expected MinIPv6Shards 2, got %d", cfg.MinIPv6Shards)
	}
	if cfg.AggregateCIDR {
		t.Errorf("expected AggregateCIDR false, got true")
	}
}

func TestUpdateIntervalSecondsInteger(t *testing.T) {
	env := map[string]string{
		"CROWDSEC_API_KEY":         "key",
		"CROWDSEC_UPDATE_INTERVAL": "60",
	}
	cfg, err := LoadFromEnv(mockLookup(env))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.UpdateInterval != 60*time.Second {
		t.Errorf("expected 60s, got %v", cfg.UpdateInterval)
	}
}

func TestInvalidConfigurations(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "invalid update interval text",
			env:  map[string]string{"CROWDSEC_API_KEY": "k", "CROWDSEC_UPDATE_INTERVAL": "invalid"},
		},
		{
			name: "negative update interval",
			env:  map[string]string{"CROWDSEC_API_KEY": "k", "CROWDSEC_UPDATE_INTERVAL": "-5s"},
		},
		{
			name: "zero update interval",
			env:  map[string]string{"CROWDSEC_API_KEY": "k", "CROWDSEC_UPDATE_INTERVAL": "0s"},
		},
		{
			name: "invalid shard size text",
			env:  map[string]string{"CROWDSEC_API_KEY": "k", "EDL_SHARD_SIZE": "abc"},
		},
		{
			name: "zero shard size",
			env:  map[string]string{"CROWDSEC_API_KEY": "k", "EDL_SHARD_SIZE": "0"},
		},
		{
			name: "invalid min ipv4 shards text",
			env:  map[string]string{"CROWDSEC_API_KEY": "k", "EDL_MIN_IPV4_SHARDS": "xyz"},
		},
		{
			name: "zero min ipv4 shards",
			env:  map[string]string{"CROWDSEC_API_KEY": "k", "EDL_MIN_IPV4_SHARDS": "0"},
		},
		{
			name: "invalid min ipv6 shards text",
			env:  map[string]string{"CROWDSEC_API_KEY": "k", "EDL_MIN_IPV6_SHARDS": "xyz"},
		},
		{
			name: "zero min ipv6 shards",
			env:  map[string]string{"CROWDSEC_API_KEY": "k", "EDL_MIN_IPV6_SHARDS": "0"},
		},
		{
			name: "invalid aggregate bool",
			env:  map[string]string{"CROWDSEC_API_KEY": "k", "EDL_AGGREGATE_CIDR": "notabool"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadFromEnv(mockLookup(tc.env))
			if err == nil {
				t.Fatalf("expected error for case %q, got nil", tc.name)
			}
		})
	}
}

func TestLoadWithOSEnv(t *testing.T) {
	_ = os.Setenv("CROWDSEC_API_KEY", "env-key")
	defer func() { _ = os.Unsetenv("CROWDSEC_API_KEY") }()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIKey != "env-key" {
		t.Errorf("expected env-key, got %q", cfg.APIKey)
	}
}
