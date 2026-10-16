package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Config holds runtime configuration options for cs-edl-bouncer.
type Config struct {
	CrowdSecURL    string
	APIKey         string
	UpdateInterval time.Duration
	Origins        []string
	DecisionTypes  []string
	ListenAddr     string
	ShardSize      int
	MinIPv4Shards  int
	MinIPv6Shards  int
	MaxIPv4Shards  int
	MaxIPv6Shards  int
	AggregateCIDR  bool
	OriginPriority []string
}

// DefaultOriginPriority keeps manual and locally detected bans when shards overflow,
// and drops community blocklist (CAPI) entries first.
var DefaultOriginPriority = []string{"cscli", "cscli-import", "console", "crowdsec", "lists", "CAPI"}

// Load reads configuration from process environment variables.
func Load() (*Config, error) {
	return LoadFromEnv(os.LookupEnv)
}

// LoadFromEnv reads configuration using the provided environment lookup function.
func LoadFromEnv(lookup func(string) (string, bool)) (*Config, error) {
	cfg := &Config{
		CrowdSecURL:    "http://crowdsec-service:8080",
		UpdateInterval: 30 * time.Second,
		DecisionTypes:  []string{"ban"},
		ListenAddr:     ":8080",
		ShardSize:      9500,
		MinIPv4Shards:  3,
		MinIPv6Shards:  1,
		AggregateCIDR:  true,
		OriginPriority: DefaultOriginPriority,
	}

	if val, ok := lookupTrimmed(lookup, "CROWDSEC_URL"); ok {
		cfg.CrowdSecURL = strings.TrimRight(val, "/")
	}

	apiKey, err := parseAPIKey(lookup)
	if err != nil {
		return nil, err
	}
	cfg.APIKey = apiKey

	if err := parseUpdateInterval(lookup, &cfg.UpdateInterval); err != nil {
		return nil, err
	}

	if val, ok := lookupTrimmed(lookup, "CROWDSEC_ORIGINS"); ok {
		cfg.Origins = splitList(val, false)
	}

	if val, ok := lookupTrimmed(lookup, "CROWDSEC_DECISION_TYPES"); ok {
		if types := splitList(val, true); len(types) > 0 {
			cfg.DecisionTypes = types
		}
	}

	if val, ok := lookupTrimmed(lookup, "LISTEN_ADDR"); ok {
		cfg.ListenAddr = val
	}

	if err := parseIntMin(lookup, "EDL_SHARD_SIZE", 1, &cfg.ShardSize); err != nil {
		return nil, err
	}
	if err := parseIntMin(lookup, "EDL_MIN_IPV4_SHARDS", 1, &cfg.MinIPv4Shards); err != nil {
		return nil, err
	}
	if err := parseIntMin(lookup, "EDL_MIN_IPV6_SHARDS", 1, &cfg.MinIPv6Shards); err != nil {
		return nil, err
	}

	if err := parseMaxShards(lookup, "EDL_MAX_IPV4_SHARDS", "EDL_MIN_IPV4_SHARDS", cfg.MinIPv4Shards, &cfg.MaxIPv4Shards); err != nil {
		return nil, err
	}
	if err := parseMaxShards(lookup, "EDL_MAX_IPV6_SHARDS", "EDL_MIN_IPV6_SHARDS", cfg.MinIPv6Shards, &cfg.MaxIPv6Shards); err != nil {
		return nil, err
	}

	if err := parseBoolEnv(lookup, "EDL_AGGREGATE_CIDR", &cfg.AggregateCIDR); err != nil {
		return nil, err
	}

	if val, ok := lookupTrimmed(lookup, "EDL_ORIGIN_PRIORITY"); ok {
		if origins := splitList(val, false); len(origins) > 0 {
			cfg.OriginPriority = origins
		}
	}

	return cfg, nil
}

func lookupTrimmed(lookup func(string) (string, bool), key string) (string, bool) {
	if val, ok := lookup(key); ok {
		if trimmed := strings.TrimSpace(val); trimmed != "" {
			return trimmed, true
		}
	}
	return "", false
}

func parseAPIKey(lookup func(string) (string, bool)) (string, error) {
	if val, ok := lookupTrimmed(lookup, "CROWDSEC_API_KEY"); ok {
		return val, nil
	}
	if val, ok := lookupTrimmed(lookup, "BOUNCER_API_KEY"); ok {
		return val, nil
	}
	return "", fmt.Errorf("CROWDSEC_API_KEY (or BOUNCER_API_KEY) is required")
}

func parseUpdateInterval(lookup func(string) (string, bool), dest *time.Duration) error {
	val, ok := lookupTrimmed(lookup, "CROWDSEC_UPDATE_INTERVAL")
	if !ok {
		return nil
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		sec, secErr := strconv.Atoi(val)
		if secErr != nil {
			return fmt.Errorf("invalid CROWDSEC_UPDATE_INTERVAL %q: %w", val, err)
		}
		d = time.Duration(sec) * time.Second
	}
	if d <= 0 {
		return fmt.Errorf("CROWDSEC_UPDATE_INTERVAL must be greater than 0")
	}
	*dest = d
	return nil
}

func parseBoolEnv(lookup func(string) (string, bool), key string, dest *bool) error {
	val, ok := lookupTrimmed(lookup, key)
	if !ok {
		return nil
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return fmt.Errorf("invalid %s %q: %w", key, val, err)
	}
	*dest = b
	return nil
}

func parseIntMin(lookup func(string) (string, bool), key string, minVal int, dest *int) error {
	val, ok := lookupTrimmed(lookup, key)
	if !ok {
		return nil
	}
	v, err := strconv.Atoi(val)
	if err != nil || v < minVal {
		return fmt.Errorf("invalid %s %q: must be integer >= %d", key, val, minVal)
	}
	*dest = v
	return nil
}

// parseMaxShards reads an optional shard cap; 0 means unlimited, otherwise it must not be below the minimum.
func parseMaxShards(lookup func(string) (string, bool), key, minKey string, minShards int, dest *int) error {
	if err := parseIntMin(lookup, key, 0, dest); err != nil {
		return err
	}
	if *dest != 0 && *dest < minShards {
		return fmt.Errorf("invalid %s %d: must be 0 (unlimited) or >= %s (%d)", key, *dest, minKey, minShards)
	}
	return nil
}

func splitList(val string, toLower bool) []string {
	fields := strings.FieldsFunc(val, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
	result := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if toLower {
			f = strings.ToLower(f)
		}
		result = append(result, f)
	}
	return result
}
