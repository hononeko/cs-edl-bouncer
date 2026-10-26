package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hononeko/cs-edl-bouncer/pkg/config"
	"github.com/hononeko/cs-edl-bouncer/pkg/crowdsec"
)

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func startTestServer(t *testing.T, cfg *config.Config) (context.CancelFunc, <-chan error, *http.Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, cfg)
	}()

	client := &http.Client{
		Timeout: 500 * time.Millisecond,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	for range 20 {
		resp, err := client.Get(fmt.Sprintf("http://%s/healthz", cfg.ListenAddr))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return cancel, errCh, client
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	t.Fatalf("server failed to start listening on %s", cfg.ListenAddr)
	return nil, nil, nil
}

func assertCleanShutdown(t *testing.T, cancel context.CancelFunc, errCh <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("run returned error on shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("run timed out waiting for clean shutdown")
	}
}

func TestRunCleanShutdown(t *testing.T) {
	var syncCount atomic.Int32

	lapiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		syncCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(crowdsec.StreamResponse{
			New: []crowdsec.Decision{
				{ID: 10, Type: "ban", Value: "1.1.1.1"},
			},
		})
	}))
	defer lapiServer.Close()

	port := getFreePort(t)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	cfg := &config.Config{
		CrowdSecURL:    lapiServer.URL,
		APIKey:         "test-key",
		UpdateInterval: 100 * time.Millisecond,
		DecisionTypes:  []string{"ban"},
		ListenAddr:     listenAddr,
		ShardSize:      9500,
		MinIPv4Shards:  3,
		MinIPv6Shards:  1,
		AggregateCIDR:  true,
	}

	cancel, errCh, client := startTestServer(t, cfg)
	defer cancel()

	// Verify shard endpoint responds
	resp, err := client.Get(fmt.Sprintf("http://%s/lists/ipv4-0.txt", listenAddr))
	if err != nil {
		t.Fatalf("GET /lists/ipv4-0.txt failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if !strings.Contains(string(body), "CrowdSec EDL") {
		t.Errorf("expected shard content, got %s", string(body))
	}

	// Wait for sync to happen
	for range 20 {
		if syncCount.Load() > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if syncCount.Load() == 0 {
		t.Errorf("expected at least one LAPI sync, got 0")
	}

	assertCleanShutdown(t, cancel, errCh)
}

func TestRunLAPIUnreachableStartup(t *testing.T) {
	port := getFreePort(t)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	cfg := &config.Config{
		CrowdSecURL:    "http://127.0.0.1:59998", // unreachable
		APIKey:         "test-key",
		UpdateInterval: 100 * time.Millisecond,
		DecisionTypes:  []string{"ban"},
		ListenAddr:     listenAddr,
		ShardSize:      9500,
		MinIPv4Shards:  3,
		MinIPv6Shards:  1,
		AggregateCIDR:  true,
	}

	cancel, errCh, _ := startTestServer(t, cfg)
	defer cancel()

	assertCleanShutdown(t, cancel, errCh)
}

func TestRunCLI(t *testing.T) {
	ctx := context.Background()

	t.Run("version", func(t *testing.T) {
		if err := runCLI(ctx, []string{"bouncer", "version"}); err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	})

	t.Run("help", func(t *testing.T) {
		if err := runCLI(ctx, []string{"bouncer", "--help"}); err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	})

	t.Run("unknown_command", func(t *testing.T) {
		err := runCLI(ctx, []string{"bouncer", "unknown-cmd"})
		if err == nil || !strings.Contains(err.Error(), "unknown command") {
			t.Errorf("expected unknown command error, got %v", err)
		}
	})

	t.Run("unifi_sync_missing_env", func(t *testing.T) {
		err := runCLI(ctx, []string{"bouncer", "unifi-sync"})
		if err == nil || !strings.Contains(err.Error(), "UNIFI_API_KEY is required") {
			t.Errorf("expected missing UNIFI_API_KEY error, got %v", err)
		}
	})
}
