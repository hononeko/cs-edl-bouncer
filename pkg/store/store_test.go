package store

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/hononeko/cs-edl-bouncer/pkg/crowdsec"
)

func TestNewStoreInitialEmptyShards(t *testing.T) {
	s := NewStore(Options{SupportedTypes: []string{"ban"}, ShardSize: 9500, MinIPv4Shards: 3, MinIPv6Shards: 1, AggregateCIDR: true})

	expectedShards := []string{
		"ipv4-0.txt",
		"ipv4-1.txt",
		"ipv4-2.txt",
		"ipv6-0.txt",
		"ipv4.txt",
		"ipv6.txt",
		"all.txt",
	}

	for _, name := range expectedShards {
		data, ok := s.GetShard(name)
		if !ok {
			t.Errorf("expected shard %q to exist immediately", name)
		}
		if len(data) == 0 {
			t.Errorf("expected shard %q not to be empty", name)
		}
	}

	data, _ := s.GetShard("ipv4-0.txt")
	expectedContent := "# CrowdSec EDL shard (count: 0)\n"
	if string(data) != expectedContent {
		t.Errorf("expected %q, got %q", expectedContent, string(data))
	}

	m := s.GetMetrics()
	if m.RawDecisions != 0 || m.IPv4Entries != 0 || m.IPv6Entries != 0 {
		t.Errorf("expected 0 entries in metrics, got %+v", m)
	}
	if m.IPv4Shards != 3 || m.IPv6Shards != 1 {
		t.Errorf("expected 3 IPv4 and 1 IPv6 shards, got %d, %d", m.IPv4Shards, m.IPv6Shards)
	}
}

func TestProcessStreamDecisionsAndShards(t *testing.T) {
	s := NewStore(Options{SupportedTypes: []string{"ban"}, ShardSize: 2, MinIPv4Shards: 3, MinIPv6Shards: 1, AggregateCIDR: true})

	resp := &crowdsec.StreamResponse{
		New: []crowdsec.Decision{
			{ID: 1, Type: "ban", Value: "192.168.0.0/24"},
			{ID: 2, Type: "BAN", Value: "192.168.1.0/24"}, // Merges with 0.0/24 -> 192.168.0.0/23
			{ID: 3, Type: "ban", Value: "10.0.0.1"},
			{ID: 4, Type: "captcha", Value: "172.16.0.1"}, // Filtered out
			{ID: 5, Type: "ban", Value: "invalid-ip"},     // Ignored
			{ID: 6, Type: "ban", Value: "2001:db8::1"},
		},
	}

	s.ProcessStream(true, resp)

	m := s.GetMetrics()
	if m.RawDecisions != 4 { // IDs 1, 2, 3, 6
		t.Errorf("expected 4 raw decisions, got %d", m.RawDecisions)
	}
	if m.IPv4Entries != 2 { // 10.0.0.1 and 192.168.0.0/23
		t.Errorf("expected 2 IPv4 entries, got %d", m.IPv4Entries)
	}
	if m.IPv6Entries != 1 { // 2001:db8::1
		t.Errorf("expected 1 IPv6 entry, got %d", m.IPv6Entries)
	}
	if m.SyncSuccessTotal != 1 {
		t.Errorf("expected 1 sync success, got %d", m.SyncSuccessTotal)
	}

	ipv4List, _ := s.GetShard("ipv4.txt")
	expectedIPv4 := "# CrowdSec EDL IPv4 (count: 2)\n10.0.0.1\n192.168.0.0/23\n"
	if string(ipv4List) != expectedIPv4 {
		t.Errorf("expected ipv4.txt:\n%s\ngot:\n%s", expectedIPv4, string(ipv4List))
	}

	ipv6List, _ := s.GetShard("ipv6.txt")
	expectedIPv6 := "# CrowdSec EDL IPv6 (count: 1)\n2001:db8::1\n"
	if string(ipv6List) != expectedIPv6 {
		t.Errorf("expected ipv6.txt:\n%s\ngot:\n%s", expectedIPv6, string(ipv6List))
	}

	// Test Deletion of specific ID
	delResp := &crowdsec.StreamResponse{
		Deleted: []crowdsec.Decision{
			{ID: 1, Type: "ban", Value: "192.168.0.0/24"},
		},
	}
	s.ProcessStream(false, delResp)
	m = s.GetMetrics()
	if m.RawDecisions != 3 {
		t.Errorf("expected 3 raw decisions after deleting ID 1, got %d", m.RawDecisions)
	}

	// 192.168.0.0/24 is deleted, so 192.168.1.0/24 remains unmerged!
	ipv4List, _ = s.GetShard("ipv4.txt")
	expectedIPv4AfterDel := "# CrowdSec EDL IPv4 (count: 2)\n10.0.0.1\n192.168.1.0/24\n"
	if string(ipv4List) != expectedIPv4AfterDel {
		t.Errorf("expected ipv4.txt after delete:\n%s\ngot:\n%s", expectedIPv4AfterDel, string(ipv4List))
	}

	// Deletion with ID 0 removes prefix directly
	delZeroResp := &crowdsec.StreamResponse{
		Deleted: []crowdsec.Decision{
			{ID: 0, Type: "ban", Value: "10.0.0.1"},
		},
	}
	s.ProcessStream(false, delZeroResp)
	m = s.GetMetrics()
	if m.IPv4Entries != 1 {
		t.Errorf("expected 1 IPv4 entry after ID 0 delete, got %d", m.IPv4Entries)
	}

	// Deletion with unknown ID removes prefix
	delUnknownIDResp := &crowdsec.StreamResponse{
		Deleted: []crowdsec.Decision{
			{ID: 9999, Type: "ban", Value: "192.168.1.0/24"},
		},
	}
	s.ProcessStream(false, delUnknownIDResp)
	m = s.GetMetrics()
	if m.IPv4Entries != 0 {
		t.Errorf("expected 0 IPv4 entries after unknown ID delete, got %d", m.IPv4Entries)
	}
}

func TestShardingOverflow(t *testing.T) {
	// Shard size 2, min shards 1
	s := NewStore(Options{SupportedTypes: []string{"ban"}, ShardSize: 2, MinIPv4Shards: 1, MinIPv6Shards: 1, AggregateCIDR: true})

	var newDecisions []crowdsec.Decision
	for i := 1; i <= 5; i++ {
		newDecisions = append(newDecisions, crowdsec.Decision{
			ID:    int64(i),
			Type:  "ban",
			Value: fmt.Sprintf("10.0.%d.0/24", i*2), // non-siblings
		})
	}

	s.ProcessStream(true, &crowdsec.StreamResponse{New: newDecisions})
	m := s.GetMetrics()
	if m.IPv4Entries != 5 {
		t.Fatalf("expected 5 IPv4 entries, got %d", m.IPv4Entries)
	}
	if m.IPv4Shards != 3 { // ceil(5 / 2) = 3 shards
		t.Errorf("expected 3 IPv4 shards, got %d", m.IPv4Shards)
	}

	s0, ok0 := s.GetShard("ipv4-0.txt")
	s1, ok1 := s.GetShard("ipv4-1.txt")
	s2, ok2 := s.GetShard("ipv4-2.txt")
	if !ok0 || !ok1 || !ok2 {
		t.Fatalf("expected ipv4-0, ipv4-1, ipv4-2 to exist")
	}

	if !strings.Contains(string(s0), "(count: 2)") {
		t.Errorf("expected s0 to have count 2: %s", string(s0))
	}
	if !strings.Contains(string(s1), "(count: 2)") {
		t.Errorf("expected s1 to have count 2: %s", string(s1))
	}
	if !strings.Contains(string(s2), "(count: 1)") {
		t.Errorf("expected s2 to have count 1: %s", string(s2))
	}
}

func TestNonAggregateMode(t *testing.T) {
	s := NewStore(Options{SupportedTypes: []string{"ban"}, ShardSize: 9500, MinIPv4Shards: 1, MinIPv6Shards: 1, AggregateCIDR: false})

	resp := &crowdsec.StreamResponse{
		New: []crowdsec.Decision{
			{ID: 1, Type: "ban", Value: "192.168.0.0/24"},
			{ID: 2, Type: "ban", Value: "192.168.1.0/24"},
			{ID: 3, Type: "ban", Value: "192.168.0.0/24"}, // duplicate
		},
	}
	s.ProcessStream(true, resp)

	m := s.GetMetrics()
	if m.IPv4Entries != 2 {
		t.Errorf("expected 2 IPv4 entries (deduplicated but not merged), got %d", m.IPv4Entries)
	}
}

func TestSyncFailure(t *testing.T) {
	s := NewStore(Options{ShardSize: 9500, MinIPv4Shards: 1, MinIPv6Shards: 1, AggregateCIDR: true})
	s.RecordSyncFailure()
	s.RecordSyncFailure()
	m := s.GetMetrics()
	if m.SyncFailureTotal != 2 {
		t.Errorf("expected 2 sync failures, got %d", m.SyncFailureTotal)
	}
}

func TestConcurrentAccess(t *testing.T) {
	s := NewStore(Options{SupportedTypes: []string{"ban"}, ShardSize: 100, MinIPv4Shards: 3, MinIPv6Shards: 1, AggregateCIDR: true})
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s.ProcessStream(false, &crowdsec.StreamResponse{
					New: []crowdsec.Decision{
						{ID: int64(workerID*1000 + j), Type: "ban", Value: fmt.Sprintf("10.%d.%d.1", workerID, j)},
					},
				})
				_, _ = s.GetShard("ipv4-0.txt")
				_ = s.GetMetrics()
			}
		}(i)
	}

	wg.Wait()
	m := s.GetMetrics()
	if m.RawDecisions != 500 {
		t.Errorf("expected 500 raw decisions, got %d", m.RawDecisions)
	}
}

func capTestStore(aggregate bool) *Store {
	return NewStore(Options{
		SupportedTypes: []string{"ban"},
		ShardSize:      2,
		MinIPv4Shards:  1,
		MaxIPv4Shards:  1,
		MinIPv6Shards:  1,
		AggregateCIDR:  aggregate,
		OriginPriority: []string{"cscli", "crowdsec", "CAPI"},
	})
}

func TestShardCapKeepsHighestPriorityOrigins(t *testing.T) {
	s := capTestStore(true)

	s.ProcessStream(true, &crowdsec.StreamResponse{New: []crowdsec.Decision{
		{ID: 1, Origin: "CAPI", Type: "ban", Value: "10.0.0.1"},
		{ID: 2, Origin: "crowdsec", Type: "ban", Value: "10.0.0.5"},
		{ID: 3, Origin: "unknown-origin", Type: "ban", Value: "10.0.0.3"},
		{ID: 4, Origin: "cscli", Type: "ban", Value: "10.0.0.9"},
	}})

	m := s.GetMetrics()
	if m.IPv4Entries != 4 {
		t.Errorf("expected 4 IPv4 entries before the cap, got %d", m.IPv4Entries)
	}
	if m.IPv4Shards != 1 {
		t.Errorf("expected shard count capped at 1, got %d", m.IPv4Shards)
	}
	if m.IPv4Capacity != 2 || m.IPv4OverflowEntries != 2 {
		t.Errorf("expected capacity 2 and overflow 2, got %d and %d", m.IPv4Capacity, m.IPv4OverflowEntries)
	}

	shard, _ := s.GetShard("ipv4-0.txt")
	expected := "# CrowdSec EDL shard (count: 2)\n10.0.0.5\n10.0.0.9\n"
	if string(shard) != expected {
		t.Errorf("expected ipv4-0.txt:\n%s\ngot:\n%s", expected, string(shard))
	}
	if _, ok := s.GetShard("ipv4-1.txt"); ok {
		t.Errorf("expected no shard beyond the cap")
	}

	// Combined lists stay complete.
	combined, _ := s.GetShard("ipv4.txt")
	if !strings.Contains(string(combined), "(count: 4)") {
		t.Errorf("expected uncapped ipv4.txt, got:\n%s", string(combined))
	}

	// Overflow clears once decisions fit again.
	s.ProcessStream(false, &crowdsec.StreamResponse{Deleted: []crowdsec.Decision{
		{ID: 1, Value: "10.0.0.1"},
		{ID: 3, Value: "10.0.0.3"},
	}})
	if m = s.GetMetrics(); m.IPv4OverflowEntries != 0 {
		t.Errorf("expected no overflow after deletions, got %d", m.IPv4OverflowEntries)
	}
}

func TestShardCapRanksAggregatedEntriesByBestOrigin(t *testing.T) {
	s := capTestStore(true)

	s.ProcessStream(true, &crowdsec.StreamResponse{New: []crowdsec.Decision{
		// 10.1.0.0/24 + 10.1.1.0/24 merge into 10.1.0.0/23, ranked by its cscli member.
		{ID: 1, Origin: "CAPI", Type: "ban", Value: "10.1.0.0/24"},
		{ID: 2, Origin: "cscli", Type: "ban", Value: "10.1.1.0/24"},
		{ID: 3, Origin: "CAPI", Type: "ban", Value: "10.2.0.1"},
		{ID: 4, Origin: "CAPI", Type: "ban", Value: "10.3.0.0/16"},
	}})

	// Ties within CAPI go to the broader /16 over the /32.
	shard, _ := s.GetShard("ipv4-0.txt")
	expected := "# CrowdSec EDL shard (count: 2)\n10.1.0.0/23\n10.3.0.0/16\n"
	if string(shard) != expected {
		t.Errorf("expected ipv4-0.txt:\n%s\ngot:\n%s", expected, string(shard))
	}
	if m := s.GetMetrics(); m.IPv4OverflowEntries != 1 {
		t.Errorf("expected overflow 1, got %d", m.IPv4OverflowEntries)
	}
}

func TestShardCapNonAggregateMode(t *testing.T) {
	s := capTestStore(false)

	s.ProcessStream(true, &crowdsec.StreamResponse{New: []crowdsec.Decision{
		{ID: 1, Origin: "CAPI", Type: "ban", Value: "10.0.0.0/24"},
		{ID: 2, Origin: "CAPI", Type: "ban", Value: "10.0.0.1"},
		{ID: 3, Origin: "crowdsec", Type: "ban", Value: "10.0.0.2"},
		// A prefix with several decisions takes its best origin.
		{ID: 4, Origin: "CAPI", Type: "ban", Value: "10.0.0.3"},
		{ID: 5, Origin: "cscli", Type: "ban", Value: "10.0.0.3"},
	}})

	shard, _ := s.GetShard("ipv4-0.txt")
	expected := "# CrowdSec EDL shard (count: 2)\n10.0.0.2\n10.0.0.3\n"
	if string(shard) != expected {
		t.Errorf("expected ipv4-0.txt:\n%s\ngot:\n%s", expected, string(shard))
	}
	if m := s.GetMetrics(); m.IPv4OverflowEntries != 2 {
		t.Errorf("expected overflow 2, got %d", m.IPv4OverflowEntries)
	}
}

func TestShardCapBelowMinUsesMin(t *testing.T) {
	s := NewStore(Options{ShardSize: 1, MinIPv4Shards: 2, MaxIPv4Shards: 1, MinIPv6Shards: 1, AggregateCIDR: true})
	s.ProcessStream(true, &crowdsec.StreamResponse{New: []crowdsec.Decision{
		{ID: 1, Type: "ban", Value: "10.0.0.1"},
		{ID: 2, Type: "ban", Value: "10.0.0.3"},
		{ID: 3, Type: "ban", Value: "10.0.0.5"},
	}})
	m := s.GetMetrics()
	if m.IPv4Shards != 2 || m.IPv4Capacity != 2 || m.IPv4OverflowEntries != 1 {
		t.Errorf("expected 2 shards, capacity 2, overflow 1, got %d, %d, %d", m.IPv4Shards, m.IPv4Capacity, m.IPv4OverflowEntries)
	}
}
