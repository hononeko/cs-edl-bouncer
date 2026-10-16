package store

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/hononeko/cs-edl-bouncer/pkg/crowdsec"
)

func TestNewStoreInitialEmptyShards(t *testing.T) {
	s := NewStore([]string{"ban"}, 9500, 3, 1, true)

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
	s := NewStore([]string{"ban"}, 2, 3, 1, true)

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
	s := NewStore([]string{"ban"}, 2, 1, 1, true)

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
	s := NewStore([]string{"ban"}, 9500, 1, 1, false)

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
	s := NewStore(nil, 9500, 1, 1, true)
	s.RecordSyncFailure()
	s.RecordSyncFailure()
	m := s.GetMetrics()
	if m.SyncFailureTotal != 2 {
		t.Errorf("expected 2 sync failures, got %d", m.SyncFailureTotal)
	}
}

func TestConcurrentAccess(t *testing.T) {
	s := NewStore([]string{"ban"}, 100, 3, 1, true)
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
