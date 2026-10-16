package store

import (
	"cmp"
	"net/netip"
	"slices"
)

// keepHighestPriority returns at most capacity entries of normalized, in their original
// (address) order, preferring entries with the best (lowest) rank.
//
// An entry's rank is the best rank among the raw prefixes it covers, so an aggregated
// entry is kept if any decision it blocks comes from a high-priority origin. Ties go
// to broader prefixes (they block more addresses per line), then to lower addresses.
// Dropping entries from an aggregated list never makes the remaining ones mergeable,
// so the result needs no re-aggregation.
func keepHighestPriority(normalized, raw []netip.Prefix, ranks map[netip.Prefix]int, aggregate bool, capacity int) []netip.Prefix {
	if len(normalized) <= capacity {
		return normalized
	}

	entryRanks := make([]int, len(normalized))
	if aggregate {
		for i := range entryRanks {
			entryRanks[i] = unranked
		}
		// Aggregated entries are disjoint and sorted by address, so the entry covering a raw
		// prefix is the last one starting at or before the raw prefix's address.
		for _, p := range raw {
			i, found := slices.BinarySearchFunc(normalized, p.Addr(), func(e netip.Prefix, a netip.Addr) int {
				return e.Addr().Compare(a)
			})
			if !found {
				i--
			}
			if i < 0 || !normalized[i].Contains(p.Addr()) {
				continue
			}
			entryRanks[i] = min(entryRanks[i], ranks[p])
		}
	} else {
		// Deduplicated entries are exactly the raw prefixes.
		for i, e := range normalized {
			entryRanks[i] = ranks[e]
		}
	}

	order := make([]int, len(normalized))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int {
		if c := cmp.Compare(entryRanks[a], entryRanks[b]); c != 0 {
			return c
		}
		if c := cmp.Compare(normalized[a].Bits(), normalized[b].Bits()); c != 0 {
			return c
		}
		return cmp.Compare(a, b)
	})

	keep := order[:capacity]
	slices.Sort(keep)
	kept := make([]netip.Prefix, len(keep))
	for i, idx := range keep {
		kept[i] = normalized[idx]
	}
	return kept
}
