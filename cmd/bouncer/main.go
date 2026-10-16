package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hononeko/cs-edl-bouncer/pkg/config"
	"github.com/hononeko/cs-edl-bouncer/pkg/crowdsec"
	"github.com/hononeko/cs-edl-bouncer/pkg/server"
	"github.com/hononeko/cs-edl-bouncer/pkg/store"
	"github.com/hononeko/cs-edl-bouncer/pkg/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("FATAL: failed to load configuration: %v", err)
	}

	if err := run(ctx, cfg); err != nil {
		log.Fatalf("FATAL: application error: %v", err)
	}
}

func run(ctx context.Context, cfg *config.Config) error {
	st := store.NewStore(store.Options{
		SupportedTypes: cfg.DecisionTypes,
		ShardSize:      cfg.ShardSize,
		MinIPv4Shards:  cfg.MinIPv4Shards,
		MinIPv6Shards:  cfg.MinIPv6Shards,
		MaxIPv4Shards:  cfg.MaxIPv4Shards,
		MaxIPv6Shards:  cfg.MaxIPv6Shards,
		AggregateCIDR:  cfg.AggregateCIDR,
		OriginPriority: cfg.OriginPriority,
	})

	client := crowdsec.NewClient(cfg.CrowdSecURL, cfg.APIKey, cfg.Origins, nil)
	srv := server.New(st)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("INFO: starting cs-edl-bouncer %s HTTP server on %s", version.Version, cfg.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
		close(serverErr)
	}()

	go syncLoop(ctx, client, st, cfg.UpdateInterval)

	select {
	case <-ctx.Done():
		log.Println("INFO: shutdown signal received")
	case err := <-serverErr:
		return fmt.Errorf("HTTP server error: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("HTTP server shutdown: %w", err)
	}

	log.Println("INFO: server stopped cleanly")
	return nil
}

func syncLoop(ctx context.Context, client *crowdsec.Client, st *store.Store, interval time.Duration) {
	startup := true

	for {
		if ctx.Err() != nil {
			return
		}

		syncCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		resp, err := client.GetStream(syncCtx, startup)
		cancel()

		var waitDuration time.Duration
		if err != nil {
			st.RecordSyncFailure()
			log.Printf("WARN: CrowdSec LAPI stream sync failed: %v", err)
			if startup {
				waitDuration = 5 * time.Second
			} else {
				waitDuration = interval
			}
		} else {
			st.ProcessStream(startup, resp)
			m := st.GetMetrics()
			log.Printf("INFO: CrowdSec stream sync successful: %d raw decisions, %d IPv4 (%d shards), %d IPv6 (%d shards)",
				m.RawDecisions, m.IPv4Entries, m.IPv4Shards, m.IPv6Entries, m.IPv6Shards)
			if m.IPv4OverflowEntries > 0 || m.IPv6OverflowEntries > 0 {
				log.Printf("WARN: shard capacity exceeded, lowest-priority entries left out of shards: %d IPv4 (capacity %d), %d IPv6 (capacity %d)",
					m.IPv4OverflowEntries, m.IPv4Capacity, m.IPv6OverflowEntries, m.IPv6Capacity)
			}
			startup = false
			waitDuration = interval
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(waitDuration):
		}
	}
}
