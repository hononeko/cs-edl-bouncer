package cidr

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParsePrefix(t *testing.T) {
	tests := []struct {
		name, input, expected string
		wantErr               bool
	}{
		{"single IPv4", "192.168.1.1", "192.168.1.1/32", false},
		{"single IPv6", "2001:db8::1", "2001:db8::1/128", false},
		{"IPv4 CIDR", "10.0.0.0/8", "10.0.0.0/8", false},
		{"IPv4 CIDR unmasked", "10.1.2.3/8", "10.0.0.0/8", false},
		{"IPv6 CIDR", "2001:db8::/32", "2001:db8::/32", false},
		{"IPv4 mapped IPv6 single", "::ffff:192.0.2.1", "192.0.2.1/32", false},
		{"IPv4 mapped IPv6 CIDR", "::ffff:192.0.2.0/120", "192.0.2.0/24", false},
		{"whitespace trimming", "   172.16.0.0/12   ", "172.16.0.0/12", false},
		{"empty string", "   ", "", true},
		{"invalid IP", "not-an-ip", "", true},
		{"invalid CIDR bits", "1.2.3.4/33", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParsePrefix(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.String() != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, p.String())
			}
		})
	}
}

func TestFormatPrefix(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1/32", "192.168.1.1"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"2001:db8::1/128", "2001:db8::1"},
		{"2001:db8::/64", "2001:db8::/64"},
	}

	for _, tc := range tests {
		p := netip.MustParsePrefix(tc.input)
		got := FormatPrefix(p)
		if got != tc.expected {
			t.Errorf("FormatPrefix(%s) = %q, expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestAggregate(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		if res := Aggregate(nil); res != nil {
			t.Errorf("expected nil for empty slice, got %v", res)
		}
	})

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name: "deduplicate and remove sub-prefixes",
			input: []string{
				"10.0.0.0/8",
				"10.0.0.0/8",
				"10.1.0.0/16",
				"10.2.3.4/32",
				"192.168.1.1/32",
			},
			expected: []string{
				"10.0.0.0/8",
				"192.168.1.1/32",
			},
		},
		{
			name: "merge adjacent sibling prefixes",
			input: []string{
				"192.168.0.0/24",
				"192.168.1.0/24",
			},
			expected: []string{
				"192.168.0.0/23",
			},
		},
		{
			name: "cascading supernet merge",
			input: []string{
				"192.168.3.0/24",
				"192.168.1.0/24",
				"192.168.0.0/24",
				"192.168.2.0/24",
			},
			expected: []string{
				"192.168.0.0/22",
			},
		},
		{
			name: "adjacent non-siblings remain separate",
			input: []string{
				"192.168.1.0/24",
				"192.168.2.0/24",
			},
			expected: []string{
				"192.168.1.0/24",
				"192.168.2.0/24",
			},
		},
		{
			name: "IPv6 supernet merge",
			input: []string{
				"2001:db8::/65",
				"2001:db8:0:0:8000::/65",
			},
			expected: []string{
				"2001:db8::/64",
			},
		},
		{
			name: "mixed IPv4 and IPv6",
			input: []string{
				"2001:db8::1/128",
				"1.1.1.0/24",
				"1.1.1.1/32",
			},
			expected: []string{
				"1.1.1.0/24",
				"2001:db8::1/128",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prefixes := make([]netip.Prefix, len(tc.input))
			for i, s := range tc.input {
				prefixes[i] = netip.MustParsePrefix(s)
			}
			res := Aggregate(prefixes)
			got := make([]string, len(res))
			for i, p := range res {
				got[i] = p.String()
			}
			if !reflect.DeepEqual(got, tc.expected) {
				t.Errorf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestFormatEntries(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		if res := FormatEntries(nil, true); len(res) != 0 {
			t.Errorf("expected empty result for nil, got %v", res)
		}
		if res := FormatEntries(nil, false); len(res) != 0 {
			t.Errorf("expected empty result for nil, got %v", res)
		}
	})

	t.Run("deduplicate without aggregation", func(t *testing.T) {
		prefixes := []netip.Prefix{
			netip.MustParsePrefix("192.168.1.1/32"),
			netip.MustParsePrefix("192.168.1.1/32"),
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("10.0.0.0/8"),
		}
		got := FormatEntries(prefixes, false)
		expected := []string{"10.0.0.0/8", "192.168.1.0/24", "192.168.1.1"}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("FormatEntries(dedup) = %v, want %v", got, expected)
		}
	})

	t.Run("aggregate merges subnets", func(t *testing.T) {
		prefixes := []netip.Prefix{
			netip.MustParsePrefix("192.168.1.1/32"),
			netip.MustParsePrefix("192.168.1.1/32"),
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("10.0.0.0/8"),
		}
		got := FormatEntries(prefixes, true)
		expected := []string{"10.0.0.0/8", "192.168.1.0/24"}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("FormatEntries(agg) = %v, want %v", got, expected)
		}
	})
}
