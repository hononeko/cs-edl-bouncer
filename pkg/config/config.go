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
	AggregateCIDR  bool
}

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
	}

	if val, ok := lookup("CROWDSEC_URL"); ok && strings.TrimSpace(val) != "" {
		cfg.CrowdSecURL = strings.TrimRight(strings.TrimSpace(val), "/")
	}

	apiKey, ok := lookup("CROWDSEC_API_KEY")
	if !ok || strings.TrimSpace(apiKey) == "" {
		apiKey, ok = lookup("BOUNCER_API_KEY")
	}
	if !ok || strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("CROWDSEC_API_KEY (or BOUNCER_API_KEY) is required")
	}
	cfg.APIKey = strings.TrimSpace(apiKey)

	if val, ok := lookup("CROWDSEC_UPDATE_INTERVAL"); ok && strings.TrimSpace(val) != "" {
		val = strings.TrimSpace(val)
		d, err := time.ParseDuration(val)
		if err != nil {
			sec, secErr := strconv.Atoi(val)
			if secErr != nil {
				return nil, fmt.Errorf("invalid CROWDSEC_UPDATE_INTERVAL %q: %w", val, err)
			}
			d = time.Duration(sec) * time.Second
		}
		if d <= 0 {
			return nil, fmt.Errorf("CROWDSEC_UPDATE_INTERVAL must be greater than 0")
		}
		cfg.UpdateInterval = d
	}

	if val, ok := lookup("CROWDSEC_ORIGINS"); ok && strings.TrimSpace(val) != "" {
		cfg.Origins = splitList(val, false)
	}

	if val, ok := lookup("CROWDSEC_DECISION_TYPES"); ok && strings.TrimSpace(val) != "" {
		types := splitList(val, true)
		if len(types) > 0 {
			cfg.DecisionTypes = types
		}
	}

	if val, ok := lookup("LISTEN_ADDR"); ok && strings.TrimSpace(val) != "" {
		cfg.ListenAddr = strings.TrimSpace(val)
	}

	if val, ok := lookup("EDL_SHARD_SIZE"); ok && strings.TrimSpace(val) != "" {
		sz, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil || sz <= 0 {
			return nil, fmt.Errorf("invalid EDL_SHARD_SIZE %q: must be integer > 0", val)
		}
		cfg.ShardSize = sz
	}

	if val, ok := lookup("EDL_MIN_IPV4_SHARDS"); ok && strings.TrimSpace(val) != "" {
		v, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil || v < 1 {
			return nil, fmt.Errorf("invalid EDL_MIN_IPV4_SHARDS %q: must be integer >= 1", val)
		}
		cfg.MinIPv4Shards = v
	}

	if val, ok := lookup("EDL_MIN_IPV6_SHARDS"); ok && strings.TrimSpace(val) != "" {
		v, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil || v < 1 {
			return nil, fmt.Errorf("invalid EDL_MIN_IPV6_SHARDS %q: must be integer >= 1", val)
		}
		cfg.MinIPv6Shards = v
	}

	if val, ok := lookup("EDL_AGGREGATE_CIDR"); ok && strings.TrimSpace(val) != "" {
		b, err := strconv.ParseBool(strings.TrimSpace(val))
		if err != nil {
			return nil, fmt.Errorf("invalid EDL_AGGREGATE_CIDR %q: %w", val, err)
		}
		cfg.AggregateCIDR = b
	}

	return cfg, nil
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
