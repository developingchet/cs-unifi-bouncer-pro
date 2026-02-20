# Design & Architecture

Rationale and architectural decisions for cs-unifi-bouncer-pro.

## Table of Contents

- [Goals](#goals)
- [Language Choice](#language-choice)
- [High-Level Architecture](#high-level-architecture)
- [Filter Pipeline](#filter-pipeline)
- [Firewall Abstraction](#firewall-abstraction)
- [Worker Pool](#worker-pool)
- [State Management](#state-management)
- [Session Recovery](#session-recovery)
- [Batch Flushing](#batch-flushing)
- [Template-Based Naming](#template-based-naming)
- [Observability](#observability)
- [Security Posture](#security-posture)
- [Testing Approach](#testing-approach)
- [Differences from Teifun2/cs-unifi-bouncer](#differences-from-teifun2cs-unifi-bouncer)

---

## Goals

1. **Correctness** — bans must be applied idempotently and survive container restarts without re-banning or double-banning IPs
2. **Performance** — handle large ban waves without overwhelming the UniFi API or blocking the CrowdSec stream
3. **Compatibility** — support both legacy WAN_IN firewall rules (UniFi Network < 8.x) and zone-based policies (≥ 8.x) from a single binary
4. **Operability** — provide enough observability (metrics, health endpoints, structured logs) to diagnose problems without attaching a debugger
5. **Security** — the bouncer handles credentials; it must not leak them and must run with minimum privilege

---

## Language Choice

Go was selected for three reasons:

1. **Single static binary** — no runtime dependency, no interpreter, no shared libraries. The binary can be copied into a distroless container with only CA certificates and timezone data. The resulting image is under 20 MB.
2. **Concurrency primitives** — goroutines and channels map directly onto the worker pool and stream processor model. The `golang.org/x/sync/errgroup` package simplifies coordinated shutdown.
3. **TLS and HTTP** — the standard library's `net/http` and `crypto/tls` packages handle UniFi and CrowdSec LAPI connections without additional dependencies.

---

## High-Level Architecture

```
CrowdSec LAPI (SSE stream)
    │
    ▼
processStream() goroutine
    │  reads *models.Decision from go-cs-bouncer
    ▼
handleDecisionBlock()
    │  8-stage filter pipeline (synchronous, in-stream)
    ▼
Worker pool (1–64 goroutines)
    │
    │  per job:
    │  1. idempotency check  (bbolt bans bucket)
    │  2. API rate gate      (bbolt rate bucket, sliding window)
    │  3. firewall manager   (ApplyBan / ApplyUnban)
    │  4. bbolt persist      (BanRecord / BanDelete)
    ▼
UniFi controller (HTTPS REST API)
    │
    ├── Firewall groups (address-group shards, batch-flushed)
    ├── Legacy WAN_IN rules (one per shard, per family)
    └── Zone-based policies (one per zone-pair, per shard, per family)
```

The stream processor runs in a dedicated goroutine. All filter stages are stateless and execute synchronously before enqueue — no lock contention, no I/O in the hot path. Workers handle all I/O operations asynchronously.

All goroutines participate in a shared `errgroup.Group` with a cancellable context. Any goroutine returning a non-nil error triggers shutdown of all others.

---

## Filter Pipeline

Decisions from CrowdSec pass through eight stages before being enqueued. Each stage that rejects a decision records a metric counter (`crowdsec_unifi_decisions_filtered_total`) with a `stage` and `reason` label.

| Stage | Condition | Rationale |
|-------|-----------|-----------|
| `action` | Decision action is not `ban` | Delete events are handled separately as unban jobs |
| `scenario-exclude` | Scenario matches a configured exclude substring | Skip scenarios inappropriate for IP banning (e.g. account compromise) |
| `origin` | Origin not in `CROWDSEC_ORIGINS` (when set) | Optionally restrict to local CrowdSec decisions |
| `scope` | Scope is not `ip` or `range` | UniFi accepts only IP addresses and CIDRs |
| `parse` | IP address is malformed | Defensive — reject garbage values from upstream |
| `private-ip` | IP is RFC 1918, loopback, link-local, or ULA | Private addresses must not be blocked at the network edge |
| `whitelist` | IP matches `BLOCK_WHITELIST` | Trusted ranges (e.g. office CGNAT) |
| `min-duration` | Decision duration is below `BLOCK_MIN_DURATION` | Filter out short test decisions |

The pipeline is implemented as a single function (`decision.Filter`) that returns a `FilterResult` struct. No goroutines, no channels — just a fast sequential check.

---

## Firewall Abstraction

The `firewall.Manager` interface exposes four operations:

```go
type Manager interface {
    EnsureInfrastructure(ctx context.Context, sites []string) error
    ApplyBan(ctx context.Context, site, ip string, ipv6 bool) error
    ApplyUnban(ctx context.Context, site, ip string, ipv6 bool) error
    Reconcile(ctx context.Context, sites []string) (*ReconcileResult, error)
}
```

Two concrete implementations sit behind this interface:

- **`legacyManager`** — manipulates firewall address groups and `WAN_IN`/`WANv6_IN` rules
- **`zoneManager`** — manipulates firewall address groups and zone policies

The `managerImpl` wraps both and selects based on the detected or configured mode. In `auto` mode, feature detection (`internal/controller/version.go`) probes the `/rest/firewallzone` endpoint per site and caches the result.

### Shard managers

Each (site, family) combination has its own `ShardManager` that tracks in-memory shadows of firewall group members. This avoids a full API round-trip for every ban — the bouncer accumulates changes in memory and flushes them as a single `PUT` request after the batch window expires.

---

## Worker Pool

The worker pool (`internal/pool`) provides bounded concurrency with backpressure:

```
Enqueue()  ──►  [ job channel (depth=POOL_QUEUE_DEPTH) ]  ──►  worker goroutines
```

Jobs that arrive when the channel is full are **dropped** (not blocked). A `crowdsec_unifi_jobs_dropped_total` counter tracks these events. The queue depth should be sized to absorb startup ban waves — the default of 4096 is sufficient for most deployments.

Each worker runs a retry loop with exponential backoff (`POOL_RETRY_BASE × 2^attempt`). On exhaustion, the job is logged and discarded. Retried jobs do not re-enter the queue — they block the worker for the backoff duration.

### Idempotency

Before calling the UniFi API, each worker checks the bbolt `bans` bucket:

- **Ban job**: if the IP is already in `bans`, skip (already applied)
- **Unban job**: if the IP is not in `bans`, skip (nothing to remove)

This makes the system safe to restart mid-stream: re-delivered decisions from CrowdSec after restart are deduplicated at this layer.

---

## State Management

Persistent state is stored in a single [bbolt](https://github.com/etcd-io/bbolt) database (`bouncer.db`) with four buckets:

| Bucket | Key | Value |
|--------|-----|-------|
| `bans` | IP string | msgpack-encoded `BanEntry` {RecordedAt, ExpiresAt, IPv6} |
| `rate` | UUID | Unix timestamp (sliding-window rate gate entries) |
| `groups` | `site/family/shard` | msgpack-encoded `GroupRecord` {UnifiID, Members, UpdatedAt} |
| `policies` | `site/family/shard` | msgpack-encoded `PolicyRecord` {UnifiID, RuleID, Mode, Priority, UpdatedAt} |

bbolt provides ACID transactions with a single writer at a time. This matches the access pattern well: the ban bucket has many concurrent readers (idempotency checks) and one writer per job (persist step). The rate bucket uses a mutex in addition to bbolt's serialisation to coordinate the sliding-window atomicity.

### Startup reconcile

On startup (when `FIREWALL_RECONCILE_ON_START=true`), the bouncer:

1. Reads all active bans from bbolt
2. Reads all firewall groups from the UniFi controller
3. Computes the symmetric difference
4. Adds missing IPs and removes unexpected IPs

This corrects drift caused by manual edits, controller restarts, or bouncer downtime. The reconcile result is logged and recorded in the `crowdsec_unifi_reconcile_duration_seconds` histogram.

### Janitor

A background goroutine runs every `JANITOR_INTERVAL` (default 1 h):

- Prunes expired bans from the `bans` bucket (entries older than `BAN_TTL`)
- Prunes expired sliding-window entries from the `rate` bucket
- Updates the `crowdsec_unifi_db_size_bytes` gauge

---

## Session Recovery

The UniFi controller may return `401 Unauthorized` when a session cookie expires or when the API key is rotated. The bouncer handles this with a mutex-guarded re-authentication mechanism:

1. Any worker that receives a 401 calls `sessionManager.EnsureAuth()`
2. The mutex ensures only one goroutine performs the re-authentication request
3. A `ReauthMinGap` timer prevents stampedes: if re-auth completed within the gap, subsequent callers skip it and assume the session is now valid
4. After successful re-auth, the failed request is retried once

This pattern prevents the thundering-herd problem when many workers encounter a 401 simultaneously.

---

## Batch Flushing

Updating a firewall group requires a `PUT` request with the full member list. Issuing one `PUT` per ban would be wasteful during ban waves.

Instead, the `ShardManager` accumulates IP additions and removals in memory and sets a `dirty` flag. A per-shard timer (controlled by `FIREWALL_BATCH_WINDOW`, default 500 ms) triggers a flush: a single `PUT` with the full updated member list.

The shard also flushes immediately when it reaches `FIREWALL_GROUP_CAPACITY`, creating a new shard if needed.

---

## Template-Based Naming

All managed UniFi objects are named using Go `text/template` patterns configured via environment variables:

- `GROUP_NAME_TEMPLATE` — address groups
- `RULE_NAME_TEMPLATE` — legacy WAN_IN rules
- `POLICY_NAME_TEMPLATE` — zone policies

Template variables include `.Family` (v4/v6), `.Index` (shard), `.Site`, `.SrcZone`, and `.DstZone`.

This design allows:

- **Multi-instance deployments** — two bouncers (e.g. production and staging) use distinct name prefixes and coexist on the same controller
- **Renaming** — operators can change naming schemes between deployments without modifying code
- **Future extensibility** — additional variables can be added without breaking existing templates

---

## Observability

### Prometheus metrics

15 metrics under the `crowdsec_unifi_` namespace cover the full lifecycle:

- **Counters**: decisions processed/filtered, jobs enqueued/dropped/processed, API calls, auth errors
- **Histograms**: API call duration (per endpoint), reconcile duration (per trigger)
- **Gauges**: active bans (per site/family), firewall group size, DB size, worker queue depth, reconcile delta

### CrowdSec usage metrics

The bouncer pushes decision telemetry to the CrowdSec LAPI `/v1/usage-metrics`
endpoint on a configurable interval (default 30 minutes, `LAPI_METRICS_PUSH_INTERVAL`).

Each push reports a delta window — counters reset after every push:

- **blocked** — new ban decisions applied per `origin` × `remediation_type` since the last push
- **processed** — total decisions handled (bans applied + deletions) since the last push

This is distinct from the Prometheus metrics, which are cumulative for operator
dashboards. The LAPI usage-metrics push is CrowdSec's telemetry mechanism for
tracking bouncer activity across the ecosystem.

On graceful shutdown, a final push is performed before the process exits so the
last window's data is not lost.

### Health endpoints

Two HTTP endpoints run on `HEALTH_ADDR` (default `:8081`):

- `GET /healthz` — liveness probe; returns 200 if the process is running
- `GET /readyz` — readiness probe; pings the UniFi controller and returns 200 only if the connection succeeds

These are used by the Docker `HEALTHCHECK` directive and Kubernetes probes.

### Structured logging

All log output is written through a `RedactWriter` that applies regexp substitutions before writing to stdout. Passwords, API keys, and Bearer tokens are replaced with `[REDACTED]`. The log format (`json` or `text`) and level are configurable.

---

## Security Posture

| Layer | Mechanism |
|-------|-----------|
| Container | Distroless base, nonroot UID 65532, read-only filesystem |
| Capabilities | `cap_drop: ALL` |
| Syscalls | Seccomp allowlist (`security/seccomp-unifi.json`) |
| Credentials | Env vars only; `_FILE` variants for secrets; never written to disk |
| Log output | `RedactWriter` masks all sensitive values |
| TLS | Minimum TLS 1.2 on all outbound connections |
| Image signing | Cosign keyless OIDC; CycloneDX SBOM on every release |
| CVE scanning | Trivy blocks release on HIGH/CRITICAL unfixed CVEs |

---

## Testing Approach

All tests are table-driven and run without external services. The test suite covers:

- **`internal/config`**: required field validation, defaults, `_FILE` injection, template syntax, zone pair parsing
- **`internal/decision`**: filter pipeline (all 8 stages), IP parsing and sanitisation, private IP detection, whitelist matching
- **`internal/firewall`**: namer template rendering, shard manager operations
- **`internal/controller`**: session management, 401 re-authentication logic
- **`internal/storage`**: bbolt ban operations, rate gate sliding window, group/policy cache
- **`internal/pool`**: enqueue, drain, retry backoff
- **`internal/logger`**: redaction patterns
- **`internal/lapi_metrics`**: Reporter construction, interval clamping, counter reset
  behaviour after push, payload structure validation, user-agent and API key headers,
  concurrent recording under the race detector, shutdown final-push
- **`internal/capabilities`**: Constant value contracts (`BouncerType`, `Layer`,
  remediation support flags) and the intentional distinction between `BouncerType`
  (used in the metrics payload `type` field) and the LAPI user-agent service token
  (`crowdsec-unifi-bouncer`, used in HTTP headers)

A `nopRecorder` no-op implementation of `MetricsRecorder` is used in handler tests
to keep them independent of the LAPI metrics reporter.

The race detector (`go test -race ./...`) is run in CI for all packages. Concurrent tests use real bbolt databases in `t.TempDir()`.

---

## Differences from Teifun2/cs-unifi-bouncer

| Feature | Teifun2 | cs-unifi-bouncer-pro |
|---------|---------|---------------------|
| State persistence | None | ACID bbolt (4 buckets) |
| Worker concurrency | Single-threaded | 1–64 worker pool |
| Ban auto-expiry | No | Yes (TTL from CrowdSec + `BAN_TTL`) |
| Multi-site | No | Yes |
| Firewall mode | Legacy only | Auto / legacy / zone |
| Object naming | Hardcoded strings | Go templates |
| Prometheus metrics | None | 15 `crowdsec_unifi_*` metrics |
| Log redaction | None | `RedactWriter` (regex-based) |
| Dry-run mode | No | Yes |
| Startup reconcile | No | Yes |
| Error handling | `log.Fatal` | Typed errors + exponential backoff retry |
| Session recovery | None | Mutex-guarded re-auth with thundering-herd guard |
| IPv6 | Limited | Full dual-stack with separate shard managers |
| Seccomp profile | None | 78-syscall allowlist |
| Image signing | None | Cosign keyless OIDC + CycloneDX SBOM |
