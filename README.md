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
- **Worker pool** — Configurable concurrency (1–64 workers) with exponential backoff retry; handles large ban waves without blocking the CrowdSec stream
- **ACID persistence** — bbolt-backed ban tracking with TTL-aware auto-expiry; bans survive container restarts and are never double-applied
- **Template-based naming** — Go templates for all managed object names; prevents conflicts in multi-instance deployments
- **Prometheus metrics** — 15 `crowdsec_unifi_*` metrics covering decisions, jobs, API calls, active bans, and more
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
| `UNIFI_HTTP_TIMEOUT` | `15s` | Per-request HTTP timeout |
| `UNIFI_API_DEBUG` | `false` | Log raw HTTP request/response bodies |

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
| `FIREWALL_BATCH_WINDOW` | `500ms` | How long to accumulate writes before flushing to API |
| `FIREWALL_API_SHARD_DELAY` | `250ms` | Minimum pause between consecutive UniFi API write calls. Prevents the controller stacking back-to-back ruleset regenerations. `0` disables. |
| `FIREWALL_FLUSH_CONCURRENCY` | `1` | Maximum concurrent group `PUT` calls in-flight. `1` = fully serialized (recommended). Increase only for multi-site setups. |
| `FIREWALL_LOG_DROPS` | `false` | Enable logging rules on the firewall objects |
| `FIREWALL_RECONCILE_ON_START` | `true` | Sync UniFi state with bbolt on startup |
| `FIREWALL_RECONCILE_INTERVAL` | `0s` | Periodic reconcile interval; `0s` = disabled |

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
| `ZONE_PAIRS` | `External->Internal` | Comma-separated `src->dst` zone pairs. `External`/`Internal` are the default UniFi 8.x names — check Settings → Firewall → Zones if you renamed them. |
| `ZONE_CONNECTION_STATES` | `new,invalid` | Connection states the policies match |
| `ZONE_POLICY_REORDER` | `true` | Reorder policies to place block rules at the top |

### Object naming

| Variable | Default | Description |
|----------|---------|-------------|
| `GROUP_NAME_TEMPLATE` | `crowdsec-block-{{.Family}}-{{.Index}}` | Go template for firewall group names |
| `RULE_NAME_TEMPLATE` | `crowdsec-drop-{{.Family}}-{{.Index}}` | Go template for legacy rule names |
| `POLICY_NAME_TEMPLATE` | `crowdsec-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}` | Go template for zone policy names |
| `OBJECT_DESCRIPTION` | `Managed by cs-unifi-bouncer-pro. Do not edit manually.` | Description field on all managed objects |

### Worker pool

| Variable | Default | Description |
|----------|---------|-------------|
| `POOL_WORKERS` | `4` | Concurrent worker goroutines (1–64) |
| `POOL_QUEUE_DEPTH` | `4096` | Bounded job queue depth |
| `POOL_MAX_RETRIES` | `3` | Max retry attempts per job before it is dropped |
| `POOL_RETRY_BASE` | `1s` | Base duration for exponential backoff |

### API rate limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `RATELIMIT_WINDOW` | `1m` | Sliding window duration |
| `RATELIMIT_MAX_CALLS` | `120` | Max API calls per window; `0` = unlimited |

### Storage & TTL

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_DIR` | `/data` | Directory for the bbolt database file |
| `BAN_TTL` | `168h` | How long to keep a ban record if CrowdSec sends no expiry (7 days) |
| `JANITOR_INTERVAL` | `1h` | How often the janitor prunes expired bans and rate entries |

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
| `DRY_RUN` | `false` | Process decisions and log actions without calling the UniFi API |
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

Creates zone firewall policies for each configured source → destination pair. Requires UniFi Network ≥ 8.x.

```bash
FIREWALL_MODE=zone
ZONE_PAIRS=External->Internal,External->IoT,External->DMZ
```

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
Worker pool (1–64 goroutines, bounded queue)
    │
    ├── 1. Idempotency check  (bbolt bans bucket)
    ├── 2. API rate gate      (bbolt rate bucket, sliding window)
    ├── 3. Firewall manager   (ApplyBan / ApplyUnban)
    └── 4. Persist to bbolt  (BanRecord / BanDelete)
    │
    ▼
UniFi controller (HTTPS REST API)
    │
    ├── Firewall groups (address-group shards, batch-flushed)
    ├── Legacy WAN_IN rules (one per shard, per family)
    └── Zone-based policies (one per zone-pair, per shard, per family)
```

For a detailed explanation of each component, see [docs/DESIGN.md](docs/DESIGN.md).

---

## Observability

### Prometheus metrics

Available at `:9090/metrics` (configurable via `METRICS_ADDR`):

| Metric | Type | Description |
|--------|------|-------------|
| `crowdsec_unifi_active_bans` | Gauge | Currently banned IPs, labelled by site and address family |
| `crowdsec_unifi_decisions_processed_total` | Counter | Decisions received from CrowdSec, by action and origin |
| `crowdsec_unifi_decisions_filtered_total` | Counter | Decisions rejected at each filter stage |
| `crowdsec_unifi_jobs_enqueued_total` | Counter | Jobs added to the worker queue |
| `crowdsec_unifi_jobs_dropped_total` | Counter | Jobs dropped due to full queue or exhausted retries |
| `crowdsec_unifi_jobs_processed_total` | Counter | Jobs completed by workers, by action and status |
| `crowdsec_unifi_api_calls_total` | Counter | UniFi API calls, by endpoint and status |
| `crowdsec_unifi_api_duration_seconds` | Histogram | UniFi API call latency |
| `crowdsec_unifi_auth_errors_total` | Counter | Authentication failures against the UniFi controller |
| `crowdsec_unifi_reauth_total` | Counter | Re-authentication attempts |
| `crowdsec_unifi_reconcile_duration_seconds` | Histogram | Full reconcile duration, by trigger type |
| `crowdsec_unifi_reconcile_delta` | Gauge | IPs added/removed during last reconcile, by site |
| `crowdsec_unifi_firewall_group_size` | Gauge | Members per firewall group shard |
| `crowdsec_unifi_db_size_bytes` | Gauge | bbolt database file size |
| `crowdsec_unifi_worker_queue_depth` | Gauge | Current number of pending jobs |

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

```bash
cs-unifi-bouncer-pro run          # Start the daemon
cs-unifi-bouncer-pro healthcheck  # Exit 0 if healthy (used by Docker HEALTHCHECK)
cs-unifi-bouncer-pro reconcile    # One-shot full reconcile then exit
cs-unifi-bouncer-pro version      # Print version and build information
```

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

## Differences from Teifun2/cs-unifi-bouncer

| Feature | Teifun2 | cs-unifi-bouncer-pro |
|---------|---------|---------------------|
| State persistence | None | ACID bbolt (4 buckets) |
| Worker concurrency | Single-threaded | 1–64 worker pool |
| Ban auto-expiry | No | Yes (TTL from CrowdSec + `BAN_TTL`) |
| Multi-site | No | Yes |
| Firewall mode | Legacy only | Auto / legacy / zone |
| Object naming | Hardcoded | Go templates |
| Prometheus metrics | None | 15 `crowdsec_unifi_*` metrics |
| Log redaction | None | `RedactWriter` |
| Dry-run mode | No | Yes |
| Startup reconcile | No | Yes |
| Error handling | `log.Fatal` | Typed errors + exponential backoff retry |
| Session recovery | None | Mutex-guarded re-auth (thundering-herd guard) |
| IPv6 | Limited | Full dual-stack with separate shard managers |
| CrowdSec usage-metrics | No | Yes (LAPI `/v1/usage-metrics`, 30m default) |
| Seccomp profile | None | 78-syscall allowlist |
| Image signing | None | Cosign keyless OIDC + CycloneDX SBOM |

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
