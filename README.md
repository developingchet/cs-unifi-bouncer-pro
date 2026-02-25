<p align="center">
  <img src="https://github.com/user-attachments/assets/cd0d1ec5-8e15-48f4-b4fb-f28dec6629c2" width="590" alt="CrowdSec Unifi Bouncer Logo" style="max-width: 100%; height: auto;">
</p>

# cs-unifi-bouncer-pro
[![Build](https://github.com/developingchet/cs-unifi-bouncer-pro/actions/workflows/release.yml/badge.svg)](https://github.com/developingchet/cs-unifi-bouncer-pro/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/developingchet/cs-unifi-bouncer-pro)](https://goreportcard.com/report/github.com/developingchet/cs-unifi-bouncer-pro)
[![Go Version](https://img.shields.io/github/go-mod/go-version/developingchet/cs-unifi-bouncer-pro)](https://github.com/developingchet/cs-unifi-bouncer-pro)
[![Docker Pulls](https://img.shields.io/docker/pulls/developingchet/cs-unifi-bouncer-pro)](https://hub.docker.com/r/developingchet/cs-unifi-bouncer-pro)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A production-grade [CrowdSec](https://crowdsec.net) bouncer for [UniFi](https://ui.com) network controllers.

Automatically translates CrowdSec ban decisions into UniFi firewall rules — blocking malicious IPs at the network edge across all configured sites, in real time.

---

## Features

- **Dual firewall modes** — Auto-detects zone-based (UniFi Network ≥ 8.x) or legacy WAN_IN rules; no manual configuration required in most deployments
- **Multi-site** — Apply bans to multiple UniFi sites simultaneously with a single bouncer instance
- **Batch sync** — IP changes are accumulated and flushed in batch at configurable intervals (default 10s), with bin-packing to fill shards before creating new ones
- **Shard management** — Automatic creation of multiple Firewall Groups / Traffic Matching Lists when IP count exceeds capacity (10,000 per shard)
- **ACID persistence** — bbolt-backed ban tracking with TTL-aware auto-expiry; bans survive container restarts and are never double-applied
- **Template-based naming** — Go templates for all managed object names; prevents conflicts in multi-instance deployments
- **Prometheus metrics** — 19 `crowdsec_unifi_*` metrics covering decisions, jobs, API calls, active bans, shard occupancy, decision latency, and circuit breaker state
- **CrowdSec usage-metrics** — Pushes decision telemetry to LAPI `/v1/usage-metrics` on a configurable interval (default 30 min); spec-compliant with CrowdSec remediation component requirements
- **RedactWriter** — Automatically masks passwords, API keys, and Bearer tokens from all log output
- **Dry-run mode** — Process decisions and log intended actions without modifying the UniFi controller
- **Startup reconcile** — Syncs UniFi firewall state with bbolt on every start to correct drift
- **Distroless image** — Under 20 MB, runs as `nonroot` (UID 65532) with read-only filesystem
- **Keyless signing** — Cosign OIDC + CycloneDX SBOM on every release

---

## Quick Start

**Prerequisites**: Docker Engine 20.10+, Docker Compose v2+, a running CrowdSec instance.

```bash
# 1. Register the bouncer with CrowdSec (copy the key — shown once)
docker exec crowdsec cscli bouncers add unifi-bouncer

# 2. Download compose file and seccomp profile
curl -O https://raw.githubusercontent.com/developingchet/cs-unifi-bouncer-pro/main/docker-compose.standalone.yml
curl -O https://raw.githubusercontent.com/developingchet/cs-unifi-bouncer-pro/main/security/seccomp-unifi.json

# 3. Configure (3 required values)
cat > .env <<'EOF'
UNIFI_URL=https://192.168.1.1
UNIFI_API_KEY=your-api-key-here        # Settings → Control Plane → API Keys
CROWDSEC_LAPI_KEY=paste-key-here       # from step 1
# Ensure CROWDSEC_LAPI_URL is reachable from the container (defaults to http://crowdsec:8080)
EOF

# 4. Start
docker compose -f docker-compose.standalone.yml up -d

# 5. Verify
docker logs -f cs-unifi-bouncer-pro
```

For the full setup guide including advanced configuration, multi-site deployments,
TLS setup, and Docker Secrets support, see [docs/SETUP.md](docs/SETUP.md).

---

## Configuration

All configuration is via environment variables. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for extended notes.

Cells marked **required** have no default and the process will exit on startup without them.
Sensitive variables (`UNIFI_API_KEY`, `UNIFI_PASSWORD`, `CROWDSEC_LAPI_KEY`) additionally accept a `_FILE` variant pointing to a file containing the secret, for use with Docker secrets and Kubernetes secret mounts.

### UniFi controller

| Variable | Default | Description |
|----------|---------|-------------|
| `UNIFI_URL` | **required** | Controller base URL, e.g. `https://192.168.1.1` |
| `UNIFI_API_KEY` | **required** ¹ | UniFi API key (preferred) |
| `UNIFI_USERNAME` | **required** ¹ | Local admin username (fallback if no API key) |
| `UNIFI_PASSWORD` | **required** ¹ | Local admin password (fallback if no API key) |
| `UNIFI_SITES` | `default` | Comma-separated list of site names to manage |
| `UNIFI_VERIFY_TLS` | `false` | Verify the controller's TLS certificate |
| `UNIFI_CA_CERT` | — | Path to a custom CA certificate file |
| `UNIFI_HTTP_TIMEOUT` | `120s` | Per-request HTTP timeout |
| `UNIFI_API_DEBUG` | `false` | Log raw HTTP request/response bodies |
| `ENABLE_IPV6` | `false` | Enable IPv6 TCP dialing to the UniFi controller. Leave `false` unless your controller is reachable over IPv6. This is separate from `FIREWALL_ENABLE_IPV6` which controls IPv6 firewall rule creation. |

¹ Provide either `UNIFI_API_KEY` **or** both `UNIFI_USERNAME` + `UNIFI_PASSWORD`.

### CrowdSec

| Variable | Default | Description |
|----------|---------|-------------|
| `CROWDSEC_LAPI_KEY` | **required** | Bouncer API key from `cscli bouncers add` |
| `CROWDSEC_LAPI_URL` | `http://crowdsec:8080` | CrowdSec LAPI base URL |
| `CROWDSEC_LAPI_VERIFY_TLS` | `true` | Verify the LAPI TLS certificate |
| `CROWDSEC_POLL_INTERVAL` | `30s` | How often to poll LAPI when SSE is unavailable |
| `CROWDSEC_ORIGINS` | — | Comma-separated allowed origins; empty = all |
| `LAPI_METRICS_PUSH_INTERVAL` | `30m` | Interval for pushing metrics to LAPI `/v1/usage-metrics`; `0` disables; minimum enforced value is `10m` |

### Decision filtering

| Variable | Default | Description |
|----------|---------|-------------|
| `BLOCK_WHITELIST` | — | Comma-separated IPs/CIDRs to never block |
| `BLOCK_SCENARIO_EXCLUDE` | — | Comma-separated scenario substrings to skip |
| `BLOCK_MIN_DURATION` | — | Ignore bans shorter than this duration, e.g. `1h` |

### Firewall

| Variable | Default | Description |
|----------|---------|-------------|
| `FIREWALL_MODE` | `auto` | `auto` (detect at startup), `legacy`, or `zone` |
| `FIREWALL_ENABLE_IPV6` | `true` | Create separate shard managers for IPv6 |
| `FIREWALL_BLOCK_ACTION` | `drop` | Rule action: `drop` or `reject` |
| `FIREWALL_GROUP_CAPACITY` | `10000` | Max IPs per firewall group shard (shared default) |
| `FIREWALL_GROUP_CAPACITY_V4` | — | Per-family override for IPv4 shard capacity |
| `FIREWALL_GROUP_CAPACITY_V6` | — | Per-family override for IPv6 shard capacity |
| `FIREWALL_API_SHARD_DELAY` | `250ms` | Minimum pause between consecutive UniFi API write calls. Prevents the controller stacking back-to-back ruleset regenerations. `0` disables. |
| `FIREWALL_FLUSH_CONCURRENCY` | `1` | Maximum concurrent group `PUT` calls in-flight. `1` = fully serialized (recommended). Increase only for multi-site setups. |
| `FIREWALL_LOG_DROPS` | `false` | Enable logging rules on the firewall objects |
| `FIREWALL_RECONCILE_ON_START` | `true` | Sync UniFi state with bbolt on startup |
| `FIREWALL_RECONCILE_INTERVAL` | `0s` | Periodic reconcile interval; `0s` = disabled |
| `SYNC_INTERVAL` | `30s` | How often dirty shards are flushed to UniFi after a decision block. Also the retry interval for failed flushes. Minimum: `5s` |
| `SHARD_LIMIT` | `10000` | Max IPs per shard before creating a new one |

### Legacy firewall mode

| Variable | Default | Description |
|----------|---------|-------------|
| `LEGACY_RULESET_V4` | `WAN_IN` | Ruleset to attach IPv4 drop rules to |
| `LEGACY_RULESET_V6` | `WANv6_IN` | Ruleset to attach IPv6 drop rules to |
| `LEGACY_RULE_INDEX_START_V4` | `22000` | First rule index for IPv4 shards |
| `LEGACY_RULE_INDEX_START_V6` | `27000` | First rule index for IPv6 shards |

### Zone-based firewall mode

| Variable | Default | Description |
|----------|---------|-------------|
| `ZONE_PAIRS` | `External->Internal` | Comma-separated `src->dst` zone pairs. Zone names are auto-resolved to UUIDs at startup; standard UUIDs and MongoDB ObjectIDs are accepted directly. `External`/`Internal` are the default UniFi 8.x names — check Settings → Firewall → Zones if you renamed them. |

### Object naming

| Variable | Default | Description |
|----------|---------|-------------|
| `GROUP_NAME_TEMPLATE` | `crowdsec-block-{{.Family}}-{{.Index}}` | Go template for firewall group names |
| `RULE_NAME_TEMPLATE` | `crowdsec-drop-{{.Family}}-{{.Index}}` | Go template for legacy rule names |
| `POLICY_NAME_TEMPLATE` | `crowdsec-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}` | Go template for zone policy names |
| `OBJECT_DESCRIPTION` | `Managed by cs-unifi-bouncer-pro. Do not edit manually.` | Description field on all managed objects |

### Batch Sync & Shard Management

| Variable | Default | Description |
|----------|---------|-------------|
| `SYNC_INTERVAL` | `30s` | How often dirty shards are retried after a failed flush. Minimum: `5s` |
| `SHARD_LIMIT` | `10000` | Maximum IPs per shard. When a shard is full, a new shard is created automatically |

**Bin-packing**: IPs are distributed across shards such that each shard is filled to capacity before a new shard is created. This minimizes the number of firewall objects created.

**Sync model**: After every CrowdSec decision batch, all dirty shards are flushed to UniFi immediately. If a flush fails, the shard stays dirty and is retried at the next `SYNC_INTERVAL` tick.

### Storage & TTL

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_DIR` | `/data` | Directory for the bbolt database file |
| `BAN_TTL` | `168h` | How long to keep a ban record if CrowdSec sends no expiry (7 days) |
| `JANITOR_INTERVAL` | `1h` | How often the janitor prunes expired bans from bbolt |

### Session management

| Variable | Default | Description |
|----------|---------|-------------|
| `SESSION_REAUTH_MIN_GAP` | `5s` | Minimum time between re-authentication attempts |
| `SESSION_REAUTH_TIMEOUT` | `10s` | Timeout for a single re-authentication attempt |

### Observability & operational

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic` |
| `LOG_FORMAT` | `json` | `json` or `text` |
| `DRY_RUN` | `false` | Safe testing mode. The bouncer connects to both the UniFi controller and CrowdSec LAPI, reads all existing state, and logs every action it *would* take — but makes zero write requests (no `POST`, `PUT`, or `DELETE` to UniFi) and does not mutate bbolt state. Reads (`GET`) are still performed so the diff output is meaningful. Turning off dry run after a dry run session starts cleanly with no phantom bbolt entries. |
| `METRICS_ENABLED` | `true` | Expose Prometheus metrics endpoint |
| `METRICS_ADDR` | `:9090` | Listen address for `/metrics` |
| `HEALTH_ADDR` | `:8081` | Listen address for `/healthz` and `/readyz` |

---

## Firewall Modes

### Auto (recommended)

Queries the UniFi controller at startup to detect zone-based firewall support. Uses zone policies on UniFi Network ≥ 8.x and legacy WAN_IN rules on older firmware. The detected mode is logged:

```json
{"level":"info","firewall_mode":"zone","msg":"firewall mode resolved"}
```

### Legacy Mode

Creates `WAN_IN` and `WANv6_IN` drop rules referencing managed address-group shards. Compatible with all UniFi Network versions.

```bash
FIREWALL_MODE=legacy
LEGACY_RULESET_V4=WAN_IN
LEGACY_RULESET_V6=WANv6_IN
LEGACY_RULE_INDEX_START_V4=22000
```

### Zone-Based Mode

Creates zone firewall policies for each configured source → destination pair via the UniFi integration v1 API. Requires UniFi Network ≥ 8.x.

Zone names are auto-resolved to UUIDs at startup. Standard UUIDs (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) and MongoDB ObjectIDs (24-char hex) are also accepted and passed through without a lookup. If a zone name cannot be found the bouncer exits with an error listing available zones.

```bash
FIREWALL_MODE=zone

# Named zones (auto-resolved)
ZONE_PAIRS=External->Internal,External->IoT,External->DMZ

# UUID pairs (passed through directly)
ZONE_PAIRS=aaaaaaaa-0000-4000-8000-aaaaaaaaaaaa->bbbbbbbb-0000-4000-8000-bbbbbbbbbbbb
```

### Policy Ordering

UniFi zone firewall evaluates policies in ascending index order — lower index means the policy is evaluated first, and the first match wins. The bouncer creates all zone policies via the UniFi integration v1 API. Policies created through this API are classified as `SYSTEM_DEFINED` origin by UniFi and cannot be reordered via the ordering endpoint — the API returns `non-user-defined-policy-ordering-forbidden`.

Correct evaluation order (allow before block) is therefore established entirely by creation sequence. Block shard policies are created lazily: a new zone policy is only provisioned when a shard becomes active with IPs to block, via an activation callback triggered on the first ban that fills the shard. The Cloudflare whitelist ALLOW policies are created during startup (by the whitelist sync step) before the bouncer loop begins processing CrowdSec decisions. On a fresh deployment, this means ALLOW policies are assigned lower indices and are therefore evaluated before any block shard policy.

After a `drain` + redeploy, the startup sequence re-establishes the same ordering automatically: ALLOW policies are recreated by the whitelist sync, and block shard policies are recreated lazily as bans are re-applied. No manual ordering configuration is required or supported.

---

## Architecture

```
CrowdSec LAPI (SSE stream)
    │
    ▼
processStream() goroutine
    │  reads decisions from go-cs-bouncer library
    ▼
8-stage filter pipeline (synchronous, stateless)
    │  action → scenario-exclude → origin → scope
    │  → parse → private-ip → whitelist → min-duration
    ▼
Job handler (inline, synchronous per decision batch)
    │
    ├── 1. Idempotency check       (bbolt bans bucket)
    ├── 2. bbolt write (ban path)  (BanRecord persisted BEFORE UniFi write — crash-safe)
    ├── 3. Firewall manager        (ApplyBan / ApplyUnban → marks shards dirty)
    └── 4. bbolt cleanup (delete)  (BanDelete after UniFi confirms removal — skipped in DRY_RUN)
    │
    ▼
SyncDirty() — flush all dirty shards to UniFi
    │  called after every decision batch; retried by periodic SYNC_INTERVAL ticker
    ▼
Firewall Shard Manager
    │
    ├── IPSet: in-memory goroutine-safe set with dirty tracking
    ├── Bin-packing: fill shards to capacity (default 10,000) before creating new ones
    └── Shard naming: crowdsec-block-{family}-{index} (v4-0, v4-1, v6-0, ...)
    │
    ▼
UniFi controller (HTTPS REST API)
    │
    ├── Traffic Matching Lists (zone mode) or Firewall Groups (legacy mode)
    └── Zone policies or Legacy WAN_IN rules (one per shard, per family)
```

For a detailed explanation of each component, see [docs/DESIGN.md](docs/DESIGN.md).

---

## Reliability

### Crash-safe write ordering (bbolt-first)

Ban decisions are persisted to bbolt **before** being applied to the UniFi controller. This bbolt-first ordering ensures that if the process crashes between the two writes, the IP is recorded in bbolt but not yet reflected in UniFi. On the next startup, `FIREWALL_RECONCILE_ON_START` detects the discrepancy and re-applies the missing bans automatically.

The delete path uses the reverse order: the IP is removed from UniFi first, then from bbolt. A crash after the UniFi call but before bbolt cleanup leaves the IP in bbolt, and reconcile adds it back — the safe outcome is always erring on the side of the ban remaining in effect.

### Circuit breaker and rate-limit backoff

If the UniFi controller returns a `429 Too Many Requests` response, the bouncer honours the `Retry-After` header and suspends all `SyncDirty` attempts until the window expires.

For persistent controller errors, a three-state circuit breaker tracks consecutive sync failures:

- **Closed** (normal) — syncs proceed as usual
- **Open** (tripped) — syncs are suspended; `crowdsec_unifi_circuit_breaker_open` is set to `1`
- **Half-open** (probing) — one probe request is allowed after the cooldown period; a success closes the breaker, a failure reopens it

The breaker opens after **5 consecutive failures** and resets to half-open after a **60-second cooldown**. These thresholds are not currently configurable via environment variables. When the breaker closes after recovery, the event is logged and the metric returns to `0`.

### No-op TML diff

Before issuing a `PUT` to the UniFi controller for a shard, the bouncer compares the current IP set against the last successfully written state. If the content is identical, the `PUT` is skipped. This eliminates unnecessary API calls during idle intervals when no new bans or unbans have arrived since the previous flush.

### Actionable zone resolution errors (did-you-mean)

If `ZONE_PAIRS` references a zone name that does not match any discovered zone, the error message includes a case-insensitive did-you-mean suggestion:

```
zone "internal" not found for site "default" (available: External, Internal, IoT);
 Did you mean "Internal" (check capitalisation)?
```

This applies both at startup (hard failure) and during SIGHUP reload (logged as a warning, existing config preserved).

---

## Observability

### Prometheus metrics

Available at `:9090/metrics` (configurable via `METRICS_ADDR`):

| Metric | Type | Description |
|--------|------|-------------|
| `crowdsec_unifi_active_bans` | Gauge | Currently banned IPs, labelled by site and address family |
| `crowdsec_unifi_decisions_processed_total` | Counter | Decisions received from CrowdSec, by action and origin |
| `crowdsec_unifi_decisions_filtered_total` | Counter | Decisions rejected at each filter stage |
| `crowdsec_unifi_api_calls_total` | Counter | UniFi API calls, by endpoint and status |
| `crowdsec_unifi_api_duration_seconds` | Histogram | UniFi API call latency |
| `crowdsec_unifi_auth_errors_total` | Counter | Authentication failures against the UniFi controller |
| `crowdsec_unifi_reauth_total` | Counter | Re-authentication attempts |
| `crowdsec_unifi_reconcile_duration_seconds` | Histogram | Full reconcile duration, by trigger type |
| `crowdsec_unifi_reconcile_delta` | Gauge | IPs added/removed during last reconcile, by site |
| `crowdsec_unifi_firewall_group_size` | Gauge | Members per firewall group shard |
| `crowdsec_unifi_db_size_bytes` | Gauge | bbolt database file size |
| `crowdsec_unifi_shard_ip_count` | Gauge | Current IP count per firewall shard (family/shard/site) |
| `crowdsec_unifi_shard_sync_total` | Counter | Shard sync attempts by family, shard, and result |
| `crowdsec_unifi_shard_sync_duration_seconds` | Histogram | Shard sync duration by family and shard |
| `crowdsec_unifi_dirty_shards` | Gauge | Shards pending sync at the last SyncDirty call |
| `crowdsec_unifi_last_sync_timestamp_seconds` | Gauge | Unix timestamp of the last completed `SyncDirty` call. Use to alert when no sync has occurred for an extended period (e.g. > 5 min) |
| `crowdsec_unifi_shard_occupancy_ratio` | Gauge | Fraction of shard capacity in use (`ip_count / shard_limit`), labelled by family, shard, site. `1.0` = shard full; alert at `> 0.9` |
| `crowdsec_unifi_decision_latency_seconds` | Histogram | Time from a CrowdSec decision passing the filter pipeline to a successful UniFi API write. Buckets: 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0 s. Alert: p95 > 10 s indicates a controller sync bottleneck |
| `crowdsec_unifi_circuit_breaker_open` | Gauge | `1` when the firewall sync circuit breaker is open (controller unreachable); `0` when closed. Alert: value == 1 for > 60 s requires immediate attention |

### CrowdSec usage metrics

The bouncer pushes decision telemetry to the CrowdSec LAPI on a configurable
interval (default 30 minutes, configurable via `LAPI_METRICS_PUSH_INTERVAL`).

Each push reports:
- **blocked** — new ban decisions applied since the last push, labelled by `origin` and `remediation_type`
- **processed** — total decisions handled (bans applied + deletions) since the last push

Counters reset after each push (delta windows, not cumulative totals).
Set `LAPI_METRICS_PUSH_INTERVAL=0` to disable.

### Health endpoints

Available at `:8081` (configurable via `HEALTH_ADDR`):

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Liveness — returns 200 if the process is running |
| `GET /readyz` | Readiness — returns 200 only if the UniFi controller is reachable |

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `run` | Start the daemon (default) |
| `healthcheck` | Exit 0 if healthy; exit 1 otherwise. Used by Docker `HEALTHCHECK`. |
| `reconcile` | Connect to UniFi and CrowdSec, run a one-shot full reconcile, then exit |
| `status` | Read-only bbolt inspection — prints ban counts, group/policy counts, DB size. Zero API calls; safe to run while the daemon is running |
| `drain` | Remove all managed firewall objects (policies, rules, shard groups) from UniFi and clean up bbolt. Requires `--force` or `--dry-run`. |
| `validate` | Load and validate configuration from environment variables — no API calls. Exits 0 on success, 1 on error. Prints a summary table of resolved config values. Safe to run in CI. |
| `diagnose` | Three-phase connectivity check: (1) config validation, (2) CrowdSec LAPI probe, (3) UniFi controller ping and zone discovery. Exits 0 when all checks pass. |
| `version` | Print version, commit hash, and build date |

```bash
cs-unifi-bouncer-pro run          # Start the daemon
cs-unifi-bouncer-pro healthcheck  # Exit 0 if healthy (used by Docker HEALTHCHECK)
cs-unifi-bouncer-pro reconcile    # One-shot full reconcile then exit
cs-unifi-bouncer-pro status       # Inspect bbolt state without API calls
cs-unifi-bouncer-pro drain --dry-run   # Preview what drain would remove
cs-unifi-bouncer-pro drain --force     # Actually remove all managed objects
cs-unifi-bouncer-pro validate     # Validate configuration (no API calls; CI-safe)
cs-unifi-bouncer-pro diagnose     # Run connectivity checks and zone discovery
cs-unifi-bouncer-pro version      # Print version and build information
```

### `status` subcommand

Opens the bbolt database in read-only mode and prints a summary table:

```
FIELD              VALUE
bans_active        1234
bans_expired       7
groups             3
policies           6
db_size_bytes      131072
last_group_update  2026-02-24T12:00:00Z
```

The `--data-dir` flag overrides the data directory (default: `DATA_DIR` env or `/data`).

### `drain` subcommand

Removes all firewall objects managed by the bouncer for each configured site:
1. Zone policies / legacy rules (referencing objects first)
2. Traffic Matching List / Firewall Group shard objects
3. Corresponding bbolt group and policy records

Requires either `--force` (execute) or `--dry-run` (log only, no changes).

### `validate` subcommand

Loads configuration from environment variables, runs all validation rules, and prints a summary table. No API calls are made — suitable for CI pipelines and pre-flight checks.

```
FIELD           VALUE
firewall_mode   zone
zone_pairs      External->Internal
sites           default
ban_ttl         168h0m0s
shard_capacity  10000
lapi_url        http://crowdsec:8080
unifi_url       https://192.168.1.1
metrics_addr    :9090
health_addr     :8081

configuration valid ✓
```

Exits 0 on success, 1 if any validation rule fails. Deprecation warnings and insecure LAPI URL warnings are printed to stderr.

### `diagnose` subcommand

Runs three-phase diagnostics and prints a tabular result:

1. **Config** — loads and validates configuration; fails fast if invalid
2. **LAPI** — probes `CROWDSEC_LAPI_URL/v1/decisions?limit=1` for reachability
3. **UniFi** — pings the controller; in zone or auto mode, lists discovered zones per configured site

```
CHECK                    STATUS  DETAIL
config_valid             PASS    mode=zone sites=[default]
lapi_reachable           PASS    http://crowdsec:8080 → 200 OK
unifi_reachable          PASS    https://192.168.1.1 ping ok
zone_discovery[default]  PASS    3 zones found
  External                       id=67a8cc9efe6c6350dfa4dcc7
  Internal                       id=67a8cc9efe6c6350dfa4dcc8
  IoT                            id=67a8cc9efe6c6350dfa4dcc9
```

Exits 0 when all checks pass, 1 if any fail. The zone list output is useful for copying UUIDs directly into `ZONE_PAIRS` when zone name resolution is unavailable (e.g. UniFi Network 10.x).

---

## SIGHUP Hot-Reload

Sending `SIGHUP` to the running daemon triggers a live reload of the zone-pair configuration without restarting:

```bash
# Docker
docker exec cs-unifi-bouncer-pro kill -HUP 1

# systemd — ExecReload=/bin/kill -HUP $MAINPID maps to the SIGHUP handler
systemctl reload cs-unifi-bouncer-pro

# Kubernetes
kubectl -n crowdsec exec -it deploy/cs-unifi-bouncer-pro -- kill -HUP 1
```

On receipt, the daemon performs a **validate-then-commit** reload:

1. Re-reads the configuration from environment variables
2. Invalidates the stale zone ID cache so the next resolution hits the API
3. Resolves all new zone names → UUIDs into a **staging map** against the live controller
4. If every zone resolves successfully, atomically commits the new pairs and updated cache
5. If any resolution fails (zone name not found, controller unreachable), the **existing configuration stays active** and an error is logged — no partial updates are applied

Only zone pair changes (`ZONE_PAIRS`) are applied via SIGHUP. All other config changes require a restart. In legacy mode, SIGHUP is a no-op (logged as a warning).

---

## Security

- Runs as UID 65532 (`nonroot`) in a distroless container — no shell, no package manager
- `cap_drop: ALL` in `docker-compose.yml` — all Linux capabilities dropped
- `read_only: true` — root filesystem is immutable; only `/tmp` and the data volume are writable
- Custom seccomp profile (`security/seccomp-unifi.json`) — 78-syscall allowlist, all others return `EPERM`
- `no-new-privileges:true` — prevents privilege escalation via setuid binaries
- `RedactWriter` masks all secrets from logs before they are written to stdout
- `_FILE` variants for all sensitive config — compatible with Docker secrets and Kubernetes secrets
- Cosign keyless image signing (OIDC) + CycloneDX SBOM on every release
- Trivy CVE scanning blocks releases on HIGH/CRITICAL unfixed vulnerabilities

For the vulnerability disclosure policy, see [SECURITY.md](SECURITY.md).

---

## Deployment

### systemd

A ready-to-use unit file with security hardening is provided at `docs/systemd/cs-unifi-bouncer-pro.service`. Full installation instructions are in [docs/systemd/README.md](docs/systemd/README.md).

**Quick install:**

```bash
sudo cp cs-unifi-bouncer-pro /usr/local/bin/
sudo mkdir -p /etc/cs-unifi-bouncer-pro
sudo cp .env.example /etc/cs-unifi-bouncer-pro/bouncer.env
sudo chmod 600 /etc/cs-unifi-bouncer-pro/bouncer.env
# Fill in UNIFI_URL, credentials, CROWDSEC_LAPI_KEY
sudo cp docs/systemd/cs-unifi-bouncer-pro.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cs-unifi-bouncer-pro
```

The unit file enables a comprehensive set of systemd hardening directives:

| Directive | Effect |
|-----------|--------|
| `DynamicUser=yes` | Transient UID/GID allocated at start; no persistent user account required |
| `CapabilityBoundingSet=` (empty) | All Linux capabilities dropped |
| `NoNewPrivileges=yes` | Prevents privilege escalation via setuid/setgid |
| `PrivateTmp=yes` | Private `/tmp` namespace |
| `PrivateDevices=yes` | No access to raw device nodes |
| `ProtectSystem=strict` | OS filesystem mounted read-only |
| `ProtectHome=yes` | Home directories inaccessible |
| `ProtectKernelTunables=yes` | `/proc/sys` and similar paths read-only |
| `ProtectKernelModules=yes` | Module loading disabled |
| `ProtectControlGroups=yes` | cgroup filesystem read-only |
| `RestrictAddressFamilies=AF_INET AF_INET6` | Only IPv4/IPv6 sockets permitted |
| `RestrictNamespaces=yes` | Namespace creation blocked |
| `LockPersonality=yes` | ABI personality locked |
| `MemoryDenyWriteExecute=yes` | No writable+executable memory mappings |
| `RestrictRealtime=yes` | Real-time scheduling blocked |
| `SystemCallFilter=@system-service` | Syscall allowlist (service profile) |

State is stored in `/var/lib/cs-unifi-bouncer-pro/` (created automatically by `StateDirectory=`). Send `SIGHUP` via `systemctl reload cs-unifi-bouncer-pro` to hot-reload zone pairs.

### Kubernetes

Manifests are provided under `docs/kubernetes/`. Full instructions are in [docs/kubernetes/README.md](docs/kubernetes/README.md).

**Key constraints:**

- **`replicas: 1` is mandatory.** bbolt does not support concurrent writers. Running two instances simultaneously will corrupt the database.
- **`strategy: Recreate`** ensures the old pod terminates before the new one starts during rollouts. Do not change this to `RollingUpdate`.
- A **`PersistentVolumeClaim`** with `ReadWriteOnce` access is required to persist the bbolt database across pod restarts. The manifest requests 1 Gi; adjust `storageClassName` if your cluster's default storage class is not suitable.

**What the manifests include:**

| File | Contents |
|------|----------|
| `docs/kubernetes/deployment.yaml` | `Deployment` (1 replica, Recreate strategy) with liveness/readiness probes, resource limits, securityContext, and PVC mount |
| `docs/kubernetes/pvc.yaml` | `PersistentVolumeClaim` for `/data` (bbolt) |
| `docs/kubernetes/secret.example.yaml` | `Secret` template — copy, fill in values, do **not** commit |
| `docs/kubernetes/networkpolicy.yaml` | `NetworkPolicy` — restricts ingress/egress to metrics (9090), health (8081), UniFi (443), LAPI (8080), and DNS (53) |

**Quick deploy:**

```bash
kubectl create namespace crowdsec
cp docs/kubernetes/secret.example.yaml my-secret.yaml
# Edit my-secret.yaml — do NOT commit
kubectl apply -f my-secret.yaml
kubectl apply -f docs/kubernetes/pvc.yaml
kubectl apply -f docs/kubernetes/deployment.yaml
kubectl apply -f docs/kubernetes/networkpolicy.yaml
kubectl -n crowdsec get pods -l app=cs-unifi-bouncer-pro
```

The pod template includes `prometheus.io/scrape: "true"` annotations for automatic scraping. Health endpoints at port `8081` are wired to the `livenessProbe` (`/healthz`) and `readinessProbe` (`/readyz`).

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/SETUP.md](docs/SETUP.md) | Full installation and deployment guide |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Complete environment variable reference |
| [docs/DESIGN.md](docs/DESIGN.md) | Architecture decisions and internals |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [docs/REFERENCES.md](docs/REFERENCES.md) | External specifications and links |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy |

---

## License

MIT — see [LICENSE](LICENSE).
