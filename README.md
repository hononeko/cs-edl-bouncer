# cs-edl-bouncer

[![GitHub Release](https://img.shields.io/github/v/release/hononeko/cs-edl-bouncer)](https://github.com/hononeko/cs-edl-bouncer/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/hononeko/cs-edl-bouncer/main.yml)](https://github.com/hononeko/cs-edl-bouncer/actions/workflows/main.yml)
[![Docker Image](https://img.shields.io/badge/Image-hononeko/cs--edl--bouncer-blue?logo=docker)](https://github.com/hononeko/cs-edl-bouncer/pkgs/container/cs-edl-bouncer)
[![Linted with golangci-lint](https://img.shields.io/badge/linted%20with-golangci--lint-00ADD8?logo=go&logoColor=white)](https://golangci-lint.run)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**`cs-edl-bouncer`** is a high-performance, lightweight, zero-dependency CrowdSec External Dynamic List (EDL) bouncer written in Go.

It connects to the CrowdSec Local API (LAPI) decisions stream and serves pre-rendered, deterministically sorted, and CIDR-aggregated blocklists over HTTP for firewalls (OPNsense, pfSense, Palo Alto Networks, FortiGate) and network appliances.

---

## Features

- **Zero External Dependencies:** Built solely using the Go standard library (`net/netip`, `net/http`).
- **CIDR Supernet Aggregation:**
  - Automatic deduplication and sub-prefix suppression (e.g. `/32` IPs already covered by `/24` or `/16` ranges are pruned).
  - Adjacent sibling prefix merging (e.g. two `/24` subnets sharing a parent `/23` are merged into `/23`), cascading backwards across the entire address space.
- **Deterministic Sharding:**
  - Slices large blocklists into shards of configurable size (default `9500` entries) to prevent firewall table limit exhaustion and memory spikes.
  - Guarantees minimum shard counts (default 3 IPv4 shards: `ipv4-0.txt`, `ipv4-1.txt`, `ipv4-2.txt`; 1 IPv6 shard: `ipv6-0.txt`) pre-populated on startup with zero-count headers, ensuring firewall pollers never receive `404 Not Found`.
- **Shard Caps with Origin Priority:**
  - Optionally caps the number of shard files (`EDL_MAX_IPV4_SHARDS`, `EDL_MAX_IPV6_SHARDS`), so a growing blocklist never spills into a file your firewall isn't subscribed to.
  - When the entries don't fit, the lowest-priority ones are left out of the shards (community blocklist entries first, manual and local bans last) and reported in the `cs_edl_overflow_entries_*` metrics.
- **Drop-in Blocklist-Mirror Compatibility:**
  - Supports `/security/blocklist.txt` (with optional `?ipv4only` or `?ipv6only` query parameters) for direct drop-in replacement of `crowdsecurity/blocklist-mirror`.
- **Prometheus Metrics:**
  - Built-in `/metrics` endpoint exporting decision counts, aggregated entries, shard allocations, and sync health.
- **Minimal Distroless Image:**
  - Runs rootless (`nonroot:nonroot`) on `gcr.io/distroless/static-debian12`, using under 15 MiB of RAM.

---

## HTTP Endpoints

| Endpoint | Description |
|---|---|
| `GET /healthz` | Liveness health probe (`200 OK`) |
| `GET /readyz` | Readiness health probe: `503` until the first successful LAPI sync, then `200 OK`. Keeps a rolling update from replacing a working instance with one serving empty lists. |
| `GET /metrics` | Prometheus text exposition format metrics |
| `GET /lists/{shard}` | Serves individual shards (e.g. `ipv4-0.txt`, `ipv4-1.txt`, `ipv6-0.txt`) and combined lists (`ipv4.txt`, `ipv6.txt`, `all.txt`) |
| `GET /security/blocklist.txt` | Drop-in blocklist-mirror compatible endpoint (`?ipv4only`, `?ipv6only`, or `all.txt`) |

---

## Configuration

`cs-edl-bouncer` is configured entirely via environment variables:

| Variable | Default | Description |
|---|---|---|
| `CROWDSEC_URL` | `http://crowdsec-service:8080` | Base URL of the CrowdSec Local API (LAPI). |
| `CROWDSEC_API_KEY` | *(Required)* | Bouncer API key generated via `cscli bouncers add <name>`. Fallback: `BOUNCER_API_KEY`. |
| `CROWDSEC_UPDATE_INTERVAL` | `30s` | Polling interval for LAPI decisions stream (e.g. `30s`, `1m`, or seconds integer `60`). |
| `CROWDSEC_ORIGINS` | *(Empty)* | Optional comma- or space-separated list of decision origins to filter (e.g. `crowdsec,cscli,CAPI,lists`). Empty means all origins. |
| `CROWDSEC_DECISION_TYPES` | `ban` | Comma- or space-separated decision action types to include (e.g. `ban`). Normalized to lowercase. |
| `LISTEN_ADDR` | `:8080` | Address and port for the HTTP server to listen on. |
| `EDL_SHARD_SIZE` | `9500` | Maximum number of IP/CIDR entries per shard. |
| `EDL_MIN_IPV4_SHARDS` | `3` | Minimum number of IPv4 shards pre-rendered (`ipv4-0.txt` to `ipv4-(N-1).txt`). |
| `EDL_MIN_IPV6_SHARDS` | `1` | Minimum number of IPv6 shards pre-rendered (`ipv6-0.txt` to `ipv6-(N-1).txt`). |
| `EDL_MAX_IPV4_SHARDS` | `0` | Maximum number of IPv4 shards; `0` means unlimited. Must be `0` or at least `EDL_MIN_IPV4_SHARDS`. See [Shard Caps](#shard-caps). |
| `EDL_MAX_IPV6_SHARDS` | `0` | Maximum number of IPv6 shards; `0` means unlimited. Must be `0` or at least `EDL_MIN_IPV6_SHARDS`. |
| `EDL_AGGREGATE_CIDR` | `true` | When `true`, enables CIDR supernet aggregation and sub-prefix suppression. |
| `EDL_ORIGIN_PRIORITY` | `cscli,cscli-import,console,crowdsec,lists,CAPI` | Decision origins from most to least important, used to choose which entries to keep when shards are capped. Unlisted origins rank last. Case-insensitive. |

### Shard Caps

Firewalls subscribe to a fixed set of shard URLs. Without a cap, a blocklist that grows past `EDL_MIN_IPV4_SHARDS × EDL_SHARD_SIZE` entries spills into a new shard (e.g. `ipv4-3.txt`) that nothing is subscribed to, and those addresses are silently not blocked.

Set `EDL_MAX_IPV4_SHARDS` to the number of shards your firewall subscribes to. When the aggregated entries exceed `EDL_MAX_IPV4_SHARDS × EDL_SHARD_SIZE`, the bouncer:

1. Ranks each entry by the most important origin among the decisions it covers, using `EDL_ORIGIN_PRIORITY`. An aggregated range that contains a single `cscli` ban ranks as `cscli`.
2. Keeps the highest-ranked entries. Ties go to broader prefixes, since they block more addresses per entry, then to lower addresses.
3. Reports the number of entries left out in `cs_edl_overflow_entries_ipv4` and logs a warning on every sync while over capacity.

The cap applies only to shard files. The combined lists (`ipv4.txt`, `ipv6.txt`, `all.txt`, `/security/blocklist.txt`) always contain every entry.

To be warned before entries are dropped, alert on `cs_edl_entries_ipv4 / cs_edl_shard_capacity_ipv4` and on `cs_edl_overflow_entries_ipv4 > 0`.

---

## Quickstart

### Generating an API Key

On your CrowdSec host or container:

```bash
cscli bouncers add edl-bouncer
```

### Docker Compose

```yaml
services:
  cs-edl-bouncer:
    image: ghcr.io/hononeko/cs-edl-bouncer:latest
    container_name: cs-edl-bouncer
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - CROWDSEC_URL=http://crowdsec:8080
      - CROWDSEC_API_KEY=your_bouncer_api_key_here
      - CROWDSEC_UPDATE_INTERVAL=30s
      - EDL_SHARD_SIZE=9500
      - EDL_MIN_IPV4_SHARDS=3
      - EDL_MIN_IPV6_SHARDS=1
      - EDL_MAX_IPV4_SHARDS=3
      - EDL_AGGREGATE_CIDR=true
```

### Firewall Configuration (OPNsense / pfSense)

1. In **Firewall > Aliases**, create a new alias:
   - **Type:** `URL Table (IPs)`
   - **URL:** `http://<bouncer-ip>:8080/lists/ipv4-0.txt`
   - **Update Frequency:** `1` (day/hour depending on preference)
2. Repeat for `ipv4-1.txt` and `ipv4-2.txt` if using multiple shards.
3. Reference the aliases in your WAN inbound or outbound drop rules.

---

## Metrics

The `/metrics` endpoint exports the following Prometheus metrics:

```text
# HELP cs_edl_decisions_raw Number of raw decisions tracked
# TYPE cs_edl_decisions_raw gauge
cs_edl_decisions_raw 15200

# HELP cs_edl_entries_ipv4 Number of aggregated/formatted IPv4 entries
# TYPE cs_edl_entries_ipv4 gauge
cs_edl_entries_ipv4 12450

# HELP cs_edl_entries_ipv6 Number of aggregated/formatted IPv6 entries
# TYPE cs_edl_entries_ipv6 gauge
cs_edl_entries_ipv6 210

# HELP cs_edl_shards_ipv4 Number of IPv4 shards generated
# TYPE cs_edl_shards_ipv4 gauge
cs_edl_shards_ipv4 3

# HELP cs_edl_shards_ipv6 Number of IPv6 shards generated
# TYPE cs_edl_shards_ipv6 gauge
cs_edl_shards_ipv6 1

# HELP cs_edl_shard_capacity_ipv4 Maximum IPv4 entries across all shards (0 = unlimited)
# TYPE cs_edl_shard_capacity_ipv4 gauge
cs_edl_shard_capacity_ipv4 28500

# HELP cs_edl_shard_capacity_ipv6 Maximum IPv6 entries across all shards (0 = unlimited)
# TYPE cs_edl_shard_capacity_ipv6 gauge
cs_edl_shard_capacity_ipv6 0

# HELP cs_edl_overflow_entries_ipv4 IPv4 entries left out of the shards because of the shard cap
# TYPE cs_edl_overflow_entries_ipv4 gauge
cs_edl_overflow_entries_ipv4 0

# HELP cs_edl_overflow_entries_ipv6 IPv6 entries left out of the shards because of the shard cap
# TYPE cs_edl_overflow_entries_ipv6 gauge
cs_edl_overflow_entries_ipv6 0

# HELP cs_edl_sync_success_total Total successful LAPI stream syncs
# TYPE cs_edl_sync_success_total counter
cs_edl_sync_success_total 840

# HELP cs_edl_sync_failure_total Total failed LAPI stream syncs
# TYPE cs_edl_sync_failure_total counter
cs_edl_sync_failure_total 0

# HELP cs_edl_last_sync_timestamp_seconds Unix timestamp of the last successful sync
# TYPE cs_edl_last_sync_timestamp_seconds gauge
cs_edl_last_sync_timestamp_seconds 1776345600
```

---

## UniFi Gateway Reconciliation (`unifi-sync`)

`cs-edl-bouncer` includes a built-in subcommand to declaratively provision, update, and self-heal External Dynamic Lists (EDLs) and Zone-Based Firewall (ZBF) rules on UniFi Cloud Gateways (e.g. UCG-Fiber, UCG-Max, UDM-Pro) running UniFi Network Application 9+ / 11+.

```bash
# Run reconciliation once
cs-edl-bouncer unifi-sync
```

### How It Works

1. **Dynamic Zone Discovery:** Resolves zone names (`External`, `Internal`, `Gateway`, `IoT`, etc.) to gateway UUIDs dynamically via `/proxy/network/v2/api/site/{site}/firewall/zone`—no hardcoded IDs.
2. **EDL Group Management:** Reconciles dynamic address groups (`CrowdSec-EDL-IPv4-0` .. `N`, `CrowdSec-EDL-IPv6-0` .. `M`) pointing to shard URLs with configurable polling intervals.
3. **Zone-Based Firewall Rules:** Creates stateful block rules across all source and destination zone pairings (`CrowdSec-EDL-<family>-<src>-><dst>-<shard>`).
4. **Precedence Batch Reordering:** Sorts rules and posts them to `firewall-policies/batch-reorder` so EDL drop rules sit in top precedence (`index: 10000+` before predefined policies).
5. **Self-Healing & Drift Detection:** Detects changes to URLs, polling intervals, rule states, or group references and repairs them idempotently.
6. **Legacy Cleanup:** Setting `PRUNE_LEGACY=true` safely purges obsolete `cs-unifi-bouncer-*` groups and legacy static block policies.

### UniFi Environment Variables

| Variable | Default | Description |
|---|---|---|
| `UNIFI_HOST` | `https://10.10.1.1` | UniFi gateway controller URL. |
| `UNIFI_API_KEY` | *(Required)* | UniFi API Key created in Gateway Settings > System > Advanced > API Keys. |
| `UNIFI_SITE` | `default` | UniFi site name. |
| `UNIFI_SKIP_TLS_VERIFY` | `true` | Skip TLS certificate verification for local gateway addresses. |
| `UNIFI_ZONE_SRC` | `External` | Comma- or space-separated list of source firewall zones. |
| `UNIFI_ZONE_DST` | `Internal, Gateway, Vpn, Hotspot, Dmz, IoT, HomeLab` | Comma- or space-separated list of destination firewall zones. |
| `EDL_BASE_URL` | `https://blocklist.kerrlab.app/lists` | Public or internal base URL where `cs-edl-bouncer` serves shards. |
| `EDL_IPV4_SHARDS` | `3` | Number of IPv4 shards to subscribe on the gateway. |
| `EDL_IPV6_SHARDS` | `1` | Number of IPv6 shards to subscribe on the gateway. |
| `EDL_UPDATE_INTERVAL_SECONDS` | `3600` | Gateway EDL polling frequency in seconds (default 1 hour). |
| `EDL_RULE_ACTION` | `BLOCK` | Firewall policy action (`BLOCK` or `DROP`). |
| `EDL_RULE_STATES` | `NEW, INVALID` | Connection states to block (`NEW`, `INVALID`, `ESTABLISHED`, `RELATED`). |
| `PRUNE_LEGACY` | `false` | When `true`, prunes legacy `cs-unifi-bouncer-*` policies and groups. |

---

## Development & Testing

```bash
# Run unit tests with race detection and coverage
go test -v -race -coverprofile=coverage.out ./...

# View coverage summary
go tool cover -func=coverage.out

# Lint code
golangci-lint run
```

---

## License

This project is licensed under the [MIT License](LICENSE).
