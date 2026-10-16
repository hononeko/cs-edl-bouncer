package cidr

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// ParsePrefix parses a CIDR string or single IP address into a masked netip.Prefix.
// IPv4-mapped IPv6 addresses are unmapped to standard IPv4 prefixes.
func ParsePrefix(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, fmt.Errorf("empty IP/CIDR string")
	}

	// Try parsing as CIDR prefix first
	if p, err := netip.ParsePrefix(raw); err == nil {
		addr := p.Addr().Unmap()
		if addr.Is4() && p.Addr().Is6() {
			newBits := p.Bits() - 96
			if newBits < 0 {
				newBits = 0
			} else if newBits > 32 {
				newBits = 32
			}
			p = netip.PrefixFrom(addr, newBits)
		} else if addr != p.Addr() {
			p = netip.PrefixFrom(addr, p.Bits())
		}
		return p.Masked(), nil
	}

	// Try parsing as single IP address
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP/CIDR %q", raw)
	}
	addr = addr.Unmap()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

// sortMaskedPrefixes returns a masked, deterministically sorted copy of prefixes.
func sortMaskedPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	list := make([]netip.Prefix, len(prefixes))
	for i, p := range prefixes {
		list[i] = p.Masked()
	}
	slices.SortFunc(list, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return cmp.Compare(a.Bits(), b.Bits())
	})
	return list
}

// Deduplicate masks, sorts deterministically, and removes exact duplicates without subnet aggregation.
func Deduplicate(prefixes []netip.Prefix) []netip.Prefix {
	list := sortMaskedPrefixes(prefixes)
	if len(list) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, p := range list {
		if len(out) > 0 && out[len(out)-1] == p {
			continue
		}
		out = append(out, p)
	}
	return out
}

// Aggregate sorts prefixes deterministically, removes duplicates and sub-prefixes,
// and merges adjacent sibling prefixes of equal bit length into their supernet,
// cascading backwards across the stack.
func Aggregate(prefixes []netip.Prefix) []netip.Prefix {
	list := sortMaskedPrefixes(prefixes)
	if len(list) == 0 {
		return nil
	}

	var stack []netip.Prefix

	for _, p := range list {
		// 1. Deduplication and sub-prefix suppression:
		// If already covered by a broader prefix on the stack, skip it.
		if len(stack) > 0 {
			last := stack[len(stack)-1]
			if last.Contains(p.Addr()) && last.Bits() <= p.Bits() {
				continue
			}
		}

		// 2. Sibling supernet merging with backwards cascading
		curr := p
		for len(stack) > 0 {
			top := stack[len(stack)-1]
			if canMerge(top, curr) {
				curr = netip.PrefixFrom(top.Addr(), top.Bits()-1).Masked()
				stack = stack[:len(stack)-1]
			} else {
				break
			}
		}
		stack = append(stack, curr)
	}

	return stack
}

func canMerge(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() {
		return false
	}
	if a.Bits() != b.Bits() || a.Bits() == 0 {
		return false
	}
	parentA := netip.PrefixFrom(a.Addr(), a.Bits()-1).Masked()
	parentB := netip.PrefixFrom(b.Addr(), b.Bits()-1).Masked()
	return parentA == parentB
}

// FormatPrefix returns a plain IP without /32 or /128 suffix for single host prefixes,
// or CIDR notation for ranges.
func FormatPrefix(p netip.Prefix) string {
	if (p.Addr().Is4() && p.Bits() == 32) || (p.Addr().Is6() && p.Bits() == 128) {
		return p.Addr().String()
	}
	return p.String()
}

// Normalize aggregates or deduplicates raw prefixes, based on the flag, into a
// deterministically sorted list.
func Normalize(prefixes []netip.Prefix, aggregate bool) []netip.Prefix {
	if aggregate {
		return Aggregate(prefixes)
	}
	return Deduplicate(prefixes)
}

// FormatPrefixes formats each prefix with FormatPrefix.
func FormatPrefixes(prefixes []netip.Prefix) []string {
	entries := make([]string, len(prefixes))
	for i, p := range prefixes {
		entries[i] = FormatPrefix(p)
	}
	return entries
}

// FormatEntries processes raw prefixes (aggregating or deduplicating based on the flag)
// and returns formatted string entries.
func FormatEntries(prefixes []netip.Prefix, aggregate bool) []string {
	return FormatPrefixes(Normalize(prefixes, aggregate))
}
