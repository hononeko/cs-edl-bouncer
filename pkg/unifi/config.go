package unifi

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"
)

// Config defines the declarative reconciliation settings for UniFi firewall and EDLs.
type Config struct {
	Host               string
	APIKey             string
	Site               string
	SkipTLSVerify      bool
	ZoneSrc            []string
	ZoneDst            []string
	BaseURL            string
	IPv4Shards         int
	IPv6Shards         int
	UpdateIntervalSecs int
	RuleAction         string
	RuleStates         []string
	PruneLegacy        bool
}

// LoadConfigFromEnv reads UniFi reconciliation settings using a lookup function.
func LoadConfigFromEnv(lookup func(string) (string, bool)) (*Config, error) {
	cfg := &Config{
		Site:               "default",
		SkipTLSVerify:      true,
		ZoneSrc:            []string{"External"},
		ZoneDst:            []string{"Internal", "Gateway", "Vpn", "Hotspot", "Dmz", "IoT", "HomeLab"},
		BaseURL:            "https://blocklist.kerrlab.app/lists",
		IPv4Shards:         3,
		IPv6Shards:         1,
		UpdateIntervalSecs: 3600,
		RuleAction:         "BLOCK",
		RuleStates:         []string{"NEW", "INVALID"},
		PruneLegacy:        false,
	}

	if val, ok := lookupTrimmed(lookup, "UNIFI_HOST"); ok {
		cfg.Host = strings.TrimRight(val, "/")
	}

	if val, ok := lookupTrimmed(lookup, "UNIFI_API_KEY"); ok {
		cfg.APIKey = val
	}
	if cfg.APIKey == "" {
		return nil, errors.New("UNIFI_API_KEY is required")
	}
	if cfg.Host == "" {
		return nil, errors.New("UNIFI_HOST is required")
	}

	if val, ok := lookupTrimmed(lookup, "UNIFI_SITE"); ok {
		cfg.Site = val
	}

	if val, ok := lookupTrimmed(lookup, "UNIFI_SKIP_TLS_VERIFY"); ok {
		parsed, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("invalid UNIFI_SKIP_TLS_VERIFY %q: must be a boolean", val)
		}
		cfg.SkipTLSVerify = parsed
	}

	if val, ok := lookupTrimmed(lookup, "UNIFI_ZONE_SRC"); ok {
		if list := splitList(val); len(list) > 0 {
			cfg.ZoneSrc = list
		}
	}

	if val, ok := lookupTrimmed(lookup, "UNIFI_ZONE_DST"); ok {
		if list := splitList(val); len(list) > 0 {
			cfg.ZoneDst = list
		}
	}

	if val, ok := lookupTrimmed(lookup, "EDL_BASE_URL"); ok {
		cfg.BaseURL = strings.TrimRight(val, "/")
	}

	if err := parseIntMin(lookup, "EDL_IPV4_SHARDS", 1, &cfg.IPv4Shards); err != nil {
		return nil, err
	}
	if err := parseIntMin(lookup, "EDL_IPV6_SHARDS", 0, &cfg.IPv6Shards); err != nil {
		return nil, err
	}
	if err := parseIntMin(lookup, "EDL_UPDATE_INTERVAL_SECONDS", 60, &cfg.UpdateIntervalSecs); err != nil {
		return nil, err
	}

	if val, ok := lookupTrimmed(lookup, "EDL_RULE_ACTION"); ok {
		cfg.RuleAction = strings.ToUpper(val)
	}

	if val, ok := lookupTrimmed(lookup, "EDL_RULE_STATES"); ok {
		if list := splitList(val); len(list) > 0 {
			for i := range list {
				list[i] = strings.ToUpper(list[i])
			}
			cfg.RuleStates = list
		}
	}

	if val, ok := lookupTrimmed(lookup, "PRUNE_LEGACY"); ok {
		parsed, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("invalid PRUNE_LEGACY %q: must be a boolean", val)
		}
		cfg.PruneLegacy = parsed
	}

	return cfg, nil
}

// LoadConfig reads UniFi reconciliation settings from the process environment.
func LoadConfig() (*Config, error) {
	return LoadConfigFromEnv(os.LookupEnv)
}

func lookupTrimmed(lookup func(string) (string, bool), key string) (string, bool) {
	val, ok := lookup(key)
	if !ok {
		return "", false
	}
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return "", false
	}
	return trimmed, true
}

func parseIntMin(lookup func(string) (string, bool), key string, minVal int, dest *int) error {
	val, ok := lookupTrimmed(lookup, key)
	if !ok {
		return nil
	}
	parsed, err := strconv.Atoi(val)
	if err != nil {
		return fmt.Errorf("invalid %s %q: must be an integer", key, val)
	}
	if parsed < minVal {
		return fmt.Errorf("invalid %s %d: must be >= %d", key, parsed, minVal)
	}
	*dest = parsed
	return nil
}

func splitList(val string) []string {
	fields := strings.FieldsFunc(val, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		trimmed := strings.TrimSpace(f)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
