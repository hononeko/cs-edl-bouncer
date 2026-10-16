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

// Metrics contains operational telemetry for Prometheus exposition.
type Metrics struct {
	RawDecisions          int64
	IPv4Entries           int64
	IPv6Entries           int64
	IPv4Shards            int64
	IPv6Shards            int64
	SyncSuccessTotal      int64
	SyncFailureTotal      int64
	LastSyncTimestampSecs int64
}

// Store maintains thread-safe decision state and pre-rendered EDL shard text.
type Store struct {
	mu             sync.RWMutex
	decisions      map[netip.Prefix]map[int64]struct{}
	renderedShards map[string][]byte
	metrics        Metrics

	supportedTypes map[string]struct{}
	shardSize      int
	minIPv4Shards  int
	minIPv6Shards  int
	aggregateCIDR  bool
}

// NewStore initializes a new decision store and pre-renders initial empty shards.
func NewStore(supportedTypes []string, shardSize, minIPv4Shards, minIPv6Shards int, aggregateCIDR bool) *Store {
	stMap := make(map[string]struct{}, len(supportedTypes))
	for _, t := range supportedTypes {
		stMap[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
	}

	s := &Store{
		decisions:      make(map[netip.Prefix]map[int64]struct{}),
		renderedShards: make(map[string][]byte),
		supportedTypes: stMap,
		shardSize:      shardSize,
		minIPv4Shards:  minIPv4Shards,
		minIPv6Shards:  minIPv6Shards,
		aggregateCIDR:  aggregateCIDR,
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
		s.decisions = make(map[netip.Prefix]map[int64]struct{})
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
		if _, ok := s.supportedTypes[strings.ToLower(strings.TrimSpace(d.Type))]; !ok {
			return
		}
	}

	p, err := cidr.ParsePrefix(d.Value)
	if err != nil {
		return
	}

	idSet, exists := s.decisions[p]
	if !exists {
		idSet = make(map[int64]struct{})
		s.decisions[p] = idSet
	}
	idSet[d.ID] = struct{}{}
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

func (s *Store) recomputeLocked() {
	var rawCount int64
	var ipv4Prefixes []netip.Prefix
	var ipv6Prefixes []netip.Prefix

	for p, idSet := range s.decisions {
		rawCount += int64(len(idSet))
		if p.Addr().Is4() {
			ipv4Prefixes = append(ipv4Prefixes, p)
		} else if p.Addr().Is6() {
			ipv6Prefixes = append(ipv6Prefixes, p)
		}
	}

	ipv4Entries := cidr.FormatEntries(ipv4Prefixes, s.aggregateCIDR)
	ipv6Entries := cidr.FormatEntries(ipv6Prefixes, s.aggregateCIDR)

	s.renderedShards = make(map[string][]byte)

	numIPv4Shards := s.renderShardsLocked("ipv4", ipv4Entries, s.minIPv4Shards)
	numIPv6Shards := s.renderShardsLocked("ipv6", ipv6Entries, s.minIPv6Shards)

	// Combined lists
	s.renderedShards["ipv4.txt"] = renderList("IPv4", ipv4Entries)
	s.renderedShards["ipv6.txt"] = renderList("IPv6", ipv6Entries)

	allEntries := make([]string, 0, len(ipv4Entries)+len(ipv6Entries))
	allEntries = append(allEntries, ipv4Entries...)
	allEntries = append(allEntries, ipv6Entries...)
	s.renderedShards["all.txt"] = renderList("All", allEntries)

	// Update metrics
	s.metrics.RawDecisions = rawCount
	s.metrics.IPv4Entries = int64(len(ipv4Entries))
	s.metrics.IPv6Entries = int64(len(ipv6Entries))
	s.metrics.IPv4Shards = int64(numIPv4Shards)
	s.metrics.IPv6Shards = int64(numIPv6Shards)
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
