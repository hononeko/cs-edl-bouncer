package store

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/hononeko/cs-edl-bouncer/pkg/cidr"
	"github.com/hononeko/cs-edl-bouncer/pkg/crowdsec"
)

// unranked is the rank of origins missing from the origin priority list; they are dropped first.
const unranked = int(^uint(0) >> 1)

// Metrics contains operational telemetry for Prometheus exposition.
type Metrics struct {
	RawDecisions          int64
	IPv4Entries           int64
	IPv6Entries           int64
	IPv4Shards            int64
	IPv6Shards            int64
	IPv4Capacity          int64
	IPv6Capacity          int64
	IPv4OverflowEntries   int64
	IPv6OverflowEntries   int64
	SyncSuccessTotal      int64
	SyncFailureTotal      int64
	LastSyncTimestampSecs int64
}

// Options configures decision filtering, aggregation and sharding.
type Options struct {
	// SupportedTypes lists the decision types to include; empty includes all types.
	SupportedTypes []string
	ShardSize      int
	MinIPv4Shards  int
	MinIPv6Shards  int
	// MaxIPv4Shards and MaxIPv6Shards cap the number of shard files; 0 means unlimited.
	// Entries that do not fit are dropped from the shards, lowest origin priority first.
	MaxIPv4Shards int
	MaxIPv6Shards int
	AggregateCIDR bool
	// OriginPriority lists decision origins from most to least important when shards
	// overflow. Origins not listed rank below all listed ones.
	OriginPriority []string
}

// family holds the per-address-family sharding settings.
type family struct {
	name      string
	minShards int
	maxShards int
}

// Store maintains thread-safe decision state and pre-rendered EDL shard text.
type Store struct {
	mu sync.RWMutex
	// decisions maps each prefix to its decision IDs and their origins.
	decisions      map[netip.Prefix]map[int64]string
	renderedShards map[string][]byte
	metrics        Metrics

	supportedTypes map[string]struct{}
	originRanks    map[string]int
	shardSize      int
	ipv4           family
	ipv6           family
	aggregateCIDR  bool
}

// NewStore initializes a new decision store and pre-renders initial empty shards.
func NewStore(opts Options) *Store {
	stMap := make(map[string]struct{}, len(opts.SupportedTypes))
	for _, t := range opts.SupportedTypes {
		stMap[normalizeKey(t)] = struct{}{}
	}

	ranks := make(map[string]int, len(opts.OriginPriority))
	for i, o := range opts.OriginPriority {
		if _, seen := ranks[normalizeKey(o)]; !seen {
			ranks[normalizeKey(o)] = i
		}
	}

	s := &Store{
		decisions:      make(map[netip.Prefix]map[int64]string),
		renderedShards: make(map[string][]byte),
		supportedTypes: stMap,
		originRanks:    ranks,
		shardSize:      opts.ShardSize,
		ipv4:           family{name: "ipv4", minShards: opts.MinIPv4Shards, maxShards: opts.MaxIPv4Shards},
		ipv6:           family{name: "ipv6", minShards: opts.MinIPv6Shards, maxShards: opts.MaxIPv6Shards},
		aggregateCIDR:  opts.AggregateCIDR,
	}

	// Immediately pre-populate empty shards and combined lists
	s.recomputeLocked()
	return s
}

// ProcessStream applies decisions from a CrowdSec LAPI stream response.
func (s *Store) ProcessStream(startup bool, streamResp *crowdsec.StreamResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if startup {
		s.decisions = make(map[netip.Prefix]map[int64]string)
	}

	if streamResp != nil {
		if !startup {
			for _, d := range streamResp.Deleted {
				s.deleteDecisionLocked(d)
			}
		}

		for _, d := range streamResp.New {
			s.addDecisionLocked(d)
		}
	}

	s.recomputeLocked()
	s.metrics.SyncSuccessTotal++
	s.metrics.LastSyncTimestampSecs = time.Now().Unix()
}

// RecordSyncFailure records an unsuccessful LAPI sync attempt.
func (s *Store) RecordSyncFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.metrics.SyncFailureTotal++
}

// Ready reports whether at least one LAPI sync has succeeded. Until then the shards
// are empty placeholders and must not replace lists served by a previous instance.
func (s *Store) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.metrics.SyncSuccessTotal > 0
}

// GetShard retrieves pre-rendered shard content by name (e.g. "ipv4-0.txt", "all.txt").
func (s *Store) GetShard(name string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.renderedShards[name]
	return data, ok
}

// GetMetrics returns a snapshot of the current store metrics.
func (s *Store) GetMetrics() Metrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.metrics
}

func (s *Store) addDecisionLocked(d crowdsec.Decision) {
	if len(s.supportedTypes) > 0 {
		if _, ok := s.supportedTypes[normalizeKey(d.Type)]; !ok {
			return
		}
	}

	p, err := cidr.ParsePrefix(d.Value)
	if err != nil {
		return
	}

	idSet, exists := s.decisions[p]
	if !exists {
		idSet = make(map[int64]string)
		s.decisions[p] = idSet
	}
	idSet[d.ID] = d.Origin
}

func (s *Store) deleteDecisionLocked(d crowdsec.Decision) {
	p, err := cidr.ParsePrefix(d.Value)
	if err != nil {
		return
	}

	if d.ID == 0 {
		delete(s.decisions, p)
		return
	}

	idSet, exists := s.decisions[p]
	if !exists {
		return
	}

	if _, hasID := idSet[d.ID]; hasID {
		delete(idSet, d.ID)
		if len(idSet) == 0 {
			delete(s.decisions, p)
		}
	} else {
		// Unknown ID for this prefix - per spec: remove prefix
		delete(s.decisions, p)
	}
}

func (s *Store) originRank(origin string) int {
	if r, ok := s.originRanks[normalizeKey(origin)]; ok {
		return r
	}
	return unranked
}

func (s *Store) recomputeLocked() {
	var rawCount int64
	var ipv4Prefixes []netip.Prefix
	var ipv6Prefixes []netip.Prefix
	ranks := make(map[netip.Prefix]int, len(s.decisions))

	for p, idSet := range s.decisions {
		rawCount += int64(len(idSet))
		rank := unranked
		for _, origin := range idSet {
			rank = min(rank, s.originRank(origin))
		}
		ranks[p] = rank

		if p.Addr().Is4() {
			ipv4Prefixes = append(ipv4Prefixes, p)
		} else if p.Addr().Is6() {
			ipv6Prefixes = append(ipv6Prefixes, p)
		}
	}

	s.renderedShards = make(map[string][]byte)

	ipv4 := s.renderFamilyLocked(s.ipv4, ipv4Prefixes, ranks)
	ipv6 := s.renderFamilyLocked(s.ipv6, ipv6Prefixes, ranks)

	// Combined lists are never capped; only shard files are.
	s.renderedShards["ipv4.txt"] = renderList("IPv4", ipv4.entries)
	s.renderedShards["ipv6.txt"] = renderList("IPv6", ipv6.entries)

	allEntries := make([]string, 0, len(ipv4.entries)+len(ipv6.entries))
	allEntries = append(allEntries, ipv4.entries...)
	allEntries = append(allEntries, ipv6.entries...)
	s.renderedShards["all.txt"] = renderList("All", allEntries)

	// Update metrics
	s.metrics.RawDecisions = rawCount
	s.metrics.IPv4Entries = int64(len(ipv4.entries))
	s.metrics.IPv6Entries = int64(len(ipv6.entries))
	s.metrics.IPv4Shards = int64(ipv4.shards)
	s.metrics.IPv6Shards = int64(ipv6.shards)
	s.metrics.IPv4Capacity = int64(ipv4.capacity)
	s.metrics.IPv6Capacity = int64(ipv6.capacity)
	s.metrics.IPv4OverflowEntries = int64(ipv4.overflow)
	s.metrics.IPv6OverflowEntries = int64(ipv6.overflow)
}

// familyResult describes the rendered lists of one address family.
type familyResult struct {
	entries  []string // all formatted entries, uncapped
	shards   int
	capacity int // maximum entries across all shards; 0 when unlimited
	overflow int // entries left out of the shards because of the cap
}

func (s *Store) renderFamilyLocked(f family, prefixes []netip.Prefix, ranks map[netip.Prefix]int) familyResult {
	normalized := cidr.Normalize(prefixes, s.aggregateCIDR)
	res := familyResult{entries: cidr.FormatPrefixes(normalized)}

	sharded := res.entries
	if f.maxShards > 0 {
		res.capacity = max(f.maxShards, f.minShards) * s.shardSize
		if len(normalized) > res.capacity {
			kept := keepHighestPriority(normalized, prefixes, ranks, s.aggregateCIDR, res.capacity)
			sharded = cidr.FormatPrefixes(kept)
			res.overflow = len(normalized) - len(kept)
		}
	}

	res.shards = s.renderShardsLocked(f.name, sharded, f.minShards)
	return res
}

func (s *Store) renderShardsLocked(prefix string, entries []string, minShards int) int {
	numShards := max((len(entries)+s.shardSize-1)/s.shardSize, minShards)
	for i := range numShards {
		start := min(i*s.shardSize, len(entries))
		end := min((i+1)*s.shardSize, len(entries))
		s.renderedShards[fmt.Sprintf("%s-%d.txt", prefix, i)] = renderList("shard", entries[start:end])
	}
	return numShards
}

func renderList(name string, entries []string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# CrowdSec EDL %s (count: %d)\n", name, len(entries))
	for _, entry := range entries {
		b.WriteString(entry)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func normalizeKey(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
