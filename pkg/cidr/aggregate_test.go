package cidr

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParsePrefix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "single IPv4",
			input:    "192.168.1.1",
			expected: "192.168.1.1/32",
		},
		{
			name:     "single IPv6",
			input:    "2001:db8::1",
			expected: "2001:db8::1/128",
		},
		{
			name:     "IPv4 CIDR",
			input:    "10.0.0.0/8",
			expected: "10.0.0.0/8",
		},
		{
			name:     "IPv4 CIDR unmasked",
			input:    "10.1.2.3/8",
			expected: "10.0.0.0/8",
		},
		{
			name:     "IPv6 CIDR",
			input:    "2001:db8::/32",
			expected: "2001:db8::/32",
		},
		{
			name:     "IPv4 mapped IPv6 single",
			input:    "::ffff:192.0.2.1",
			expected: "192.0.2.1/32",
		},
		{
			name:     "IPv4 mapped IPv6 CIDR",
			input:    "::ffff:192.0.2.0/120",
			expected: "192.0.2.0/24",
		},
		{
			name:     "whitespace trimming",
			input:    "   172.16.0.0/12   ",
			expected: "172.16.0.0/12",
		},
		{
			name:    "empty string",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "invalid IP",
			input:   "not-an-ip",
			wantErr: true,
		},
		{
			name:    "invalid CIDR bits",
			input:   "1.2.3.4/33",
			wantErr: true,
		},
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
		res := Aggregate(nil)
		if res != nil {
			t.Errorf("expected nil for empty slice, got %v", res)
		}
	})

	t.Run("deduplicate and remove sub-prefixes", func(t *testing.T) {
		prefixes := []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("10.1.0.0/16"),
			netip.MustParsePrefix("10.2.3.4/32"),
			netip.MustParsePrefix("192.168.1.1/32"),
		}
		expected := []string{
			"10.0.0.0/8",
			"192.168.1.1/32",
		}

		res := Aggregate(prefixes)
		got := make([]string, len(res))
		for i, p := range res {
			got[i] = p.String()
		}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})

	t.Run("merge adjacent sibling prefixes", func(t *testing.T) {
		prefixes := []netip.Prefix{
			netip.MustParsePrefix("192.168.0.0/24"),
			netip.MustParsePrefix("192.168.1.0/24"),
		}
		expected := []string{
			"192.168.0.0/23",
		}

		res := Aggregate(prefixes)
		got := make([]string, len(res))
		for i, p := range res {
			got[i] = p.String()
		}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})

	t.Run("cascading supernet merge", func(t *testing.T) {
		prefixes := []netip.Prefix{
			netip.MustParsePrefix("192.168.3.0/24"),
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("192.168.0.0/24"),
			netip.MustParsePrefix("192.168.2.0/24"),
		}
		expected := []string{
			"192.168.0.0/22",
		}

		res := Aggregate(prefixes)
		got := make([]string, len(res))
		for i, p := range res {
			got[i] = p.String()
		}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})

	t.Run("adjacent non-siblings remain separate", func(t *testing.T) {
		prefixes := []netip.Prefix{
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("192.168.2.0/24"),
		}
		expected := []string{
			"192.168.1.0/24",
			"192.168.2.0/24",
		}

		res := Aggregate(prefixes)
		got := make([]string, len(res))
		for i, p := range res {
			got[i] = p.String()
		}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})

	t.Run("IPv6 supernet merge", func(t *testing.T) {
		prefixes := []netip.Prefix{
			netip.MustParsePrefix("2001:db8::/65"),
			netip.MustParsePrefix("2001:db8:0:0:8000::/65"),
		}
		expected := []string{
			"2001:db8::/64",
		}

		res := Aggregate(prefixes)
		got := make([]string, len(res))
		for i, p := range res {
			got[i] = p.String()
		}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})

	t.Run("mixed IPv4 and IPv6", func(t *testing.T) {
		prefixes := []netip.Prefix{
			netip.MustParsePrefix("2001:db8::1/128"),
			netip.MustParsePrefix("1.1.1.0/24"),
			netip.MustParsePrefix("1.1.1.1/32"),
		}
		expected := []string{
			"1.1.1.0/24",
			"2001:db8::1/128",
		}

		res := Aggregate(prefixes)
		got := make([]string, len(res))
		for i, p := range res {
			got[i] = p.String()
		}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("expected %v, got %v", expected, got)
		}
	})
}
