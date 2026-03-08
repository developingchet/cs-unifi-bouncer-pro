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
2. **Concurrency primitives** — goroutines and channels map directly onto the stream processor and periodic sync model. The `golang.org/x/sync/errgroup` package simplifies coordinated shutdown.
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
job handler (inline, per decision)
    │  1. idempotency check  (bbolt bans bucket)
    │  2. firewall manager   (ApplyBan / ApplyUnban → mark shard dirty)
    │  3. bbolt persist      (BanRecord / BanDelete)
    ▼
SyncDirty() — flush dirty shards to UniFi (after every decision batch)
    │  periodic SYNC_INTERVAL ticker retries failed flushes
    ▼
UniFi controller (HTTPS REST API)
    │
    ├── Traffic Matching Lists / Firewall groups (shards, batch-flushed)
    ├── Legacy WAN_IN rules (one per shard, per family)
    └── Zone-based policies (one per zone-pair, per shard, per family)
```

The stream processor runs in a dedicated goroutine. All filter stages are stateless and execute synchronously. The job handler runs inline — no queuing, no retries at the job layer.

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

The `firewall.Manager` interface exposes the following operations:

```go
type Manager interface {
    EnsureInfrastructure(ctx context.Context, sites []string) error
    ApplyBan(ctx context.Context, site, ip string, ipv6 bool) error
    ApplyBanWithZones(ctx context.Context, site, ip string, ipv6 bool, zonePairs []config.ZonePair) error
    ApplyUnban(ctx context.Context, site, ip string, ipv6 bool) error
    Reconcile(ctx context.Context, sites []string) (*ReconcileResult, error)
    SyncDirty(ctx context.Context, sites []string) error
    Drain(ctx context.Context, sites []string) error
    ZoneManager() *ZoneManager
}
```

`ApplyBanWithZones` is used by the job handler when `ZONE_PAIRS_SCENARIO_MAP` provides an override for the decision's scenario. In Phase 1 the IP is routed to the default shard while the override pairs are logged; per-scenario shard provisioning is reserved for a future release.

Two concrete implementations sit behind this interface:

- **`legacyManager`** — manipulates firewall address groups and `WAN_IN`/`WANv6_IN` rules
- **`zoneManager`** — manipulates firewall address groups and zone policies

The `managerImpl` wraps both and selects based on the detected or configured mode. In `auto` mode, feature detection (`internal/controller/version.go`) probes the `/rest/firewallzone` endpoint per site and caches the result.

#### Zone policy portFilter constraint

The UniFi zone policy API has two portFilter constraints:

1. **Nesting**: `portFilter` must be nested inside `trafficFilter` on both source and destination — the POST endpoint rejects it as an unknown property if placed at the top level of `$.source` or `$.destination`.
2. **`trafficFilter.type`**: When the only filter required is port-based (no IP/network filter), `trafficFilter.type` must be `"PORT"`. Using `"NETWORK"` requires a non-null `networkFilter`; using `"IP_ADDRESS"` requires a non-null `ipAddressFilter`. `"PORT"` is the dedicated port-only type and accepts only `portFilter`.
3. **PUT exclusion**: The PUT endpoint (`/v1/firewall/policies/{id}`) rejects `portFilter` even when correctly nested. The wire structs used for PUT (`apiV1PolicyUpdateSrc` / `apiV1PolicyUpdateDst`) intentionally omit `trafficFilter.portFilter` — the server preserves the existing value on update. When portFilter needs to be added or changed on an existing policy, the bouncer deletes the existing policy and recreates it via POST. This is logged at `info` level with the message `portFilter changed — deleting policy for recreation with new portFilter`.

#### Orphan cleanup

When a zone pair is removed from `ZONE_PAIRS` or `CLOUDFLARE_ZONE_PAIRS`, previously managed firewall objects are automatically cleaned up:

- **Block policies**: at `EnsurePolicies` time, two complementary sweeps run. Pass 1 (bbolt-based): any policy recorded in bbolt for the site under mode `zone` whose name is no longer produced by the current config is deleted from UniFi and removed from bbolt — but only if it bears the managed description and `Action == "BLOCK"`. Pass 2 (API-based): any API policy with the managed description and `Action == "BLOCK"` that is not in the expected name set is deleted, even if bbolt has no record of it (wiped database, mode switch, prior installation).
- **Legacy rules**: at `EnsureRules` time, the API-level orphan sweep deletes any pre-existing rule whose `Description`, `Action`, `Ruleset`, and non-empty `SrcFirewallGroupIDs` all match what the bouncer creates, but whose name is not in the currently-expected shard name set.
- **Block port TMLs**: at `Bootstrap` time, Traffic Matching Lists named `crowdsec-ports-src-*`, `crowdsec-ports-dst-*`, `crowdsec-dstips-v4-*`, and `crowdsec-dstips-v6-*` not required by any current zone pair are deleted.
- **Cloudflare ALLOW policies**: at each Cloudflare sync, policies with the `crowdsec-whitelist-cloudflare-` prefix not in the current `CLOUDFLARE_ZONE_PAIRS` set are deleted. Policies with our managed description or an empty description (old policies created before description support) are considered bouncer-owned. UniFi's auto-created `(Return)` mirror policies are cleaned up when their corresponding forward policy is orphaned. When `CLOUDFLARE_WHITELIST_ENABLED=false`, `Manager.Drain()` removes all `crowdsec-whitelist-cloudflare-*` policies and TMLs at startup.
- **Cloudflare port TMLs**: at each Cloudflare sync, TMLs named `crowdsec-whitelist-cloudflare-srcports-*`, `crowdsec-whitelist-cloudflare-dstports-*`, and `crowdsec-whitelist-cloudflare-dstips-*` not required by any current Cloudflare zone pair are deleted.

User-created policies and TMLs are never touched — ownership requires matching both the managed description **and** the structural signature of objects the bouncer creates (action, ruleset, source group).

### Shard managers

Each (site, family) combination has its own `ShardManager` that tracks in-memory shadows of firewall group members. This avoids a full API round-trip for every ban — the bouncer accumulates changes in memory and flushes them as a single `PUT` request after the batch window expires.

---

## Decision Handling

Ban and unban decisions are processed synchronously per CrowdSec decision batch. The job handler runs inline in the `processStream` goroutine:

1. **Idempotency check** — consult the bbolt `bans` bucket:
   - Ban job: if the IP is already in `bans`, skip (already applied)
   - Unban job: if the IP is not in `bans`, skip (nothing to remove)
2. **Firewall manager** — call `ApplyBan` / `ApplyUnban`, which marks the relevant shard as dirty in memory
3. **Persist to bbolt** — write `BanRecord` / `BanDelete` (skipped in `DRY_RUN`)

After all decisions in the batch are processed, `SyncDirty` flushes all dirty shards to the UniFi API. If a flush fails, the shard stays dirty and is retried at the next `SYNC_INTERVAL` tick.

This makes the system safe to restart mid-stream: re-delivered decisions from CrowdSec after reconnect are deduplicated at the idempotency layer.

---

## State Management

Persistent state is stored in a single [bbolt](https://github.com/etcd-io/bbolt) database (`bouncer.db`) with three buckets:

| Bucket | Key | Value |
|--------|-----|-------|
| `bans` | IP string | msgpack-encoded `BanEntry` {RecordedAt, ExpiresAt, IPv6} |
| `groups` | `site/family/shard` | msgpack-encoded `GroupRecord` {UnifiID, Members, UpdatedAt} |
| `policies` | `site/family/shard` | msgpack-encoded `PolicyRecord` {UnifiID, RuleID, Mode, Priority, UpdatedAt} |
| `events` | uint64 big-endian sequence | JSON-encoded `EventEntry` {Action, Origin, Scenario, IP, RecordedAt} |

The `events` bucket is a ring buffer. Keys are auto-incrementing uint64 values encoded as 8-byte big-endian, which guarantees chronological cursor iteration. When the entry count exceeds `HISTORY_MAX_EVENTS`, the oldest entries (lowest keys) are pruned in the same write transaction. The key count is determined by cursor iteration rather than `Stats().KeyN` (which reflects stats at transaction start, not after mid-transaction mutations).

bbolt provides ACID transactions with a single writer at a time. This matches the access pattern well: the ban bucket has many concurrent readers (idempotency checks) and one writer per decision batch (persist step).

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
- Calls `ApplyUnban` on the firewall manager for each pruned IP
- Writes an `action=expire` event to the audit trail ring buffer
- Updates the `crowdsec_unifi_db_size_bytes` gauge

### Ban History (Audit Trail)

Every successful ban, unban, and janitor expiry is appended to the `events` bucket as an `EventEntry`. The `Store` interface exposes three query methods:

- `RecordEvent(e EventEntry) error` — append an event (ring-buffer eviction on overflow)
- `ListEvents(limit int) ([]EventEntry, error)` — newest-first, bounded by `limit`
- `ListEventsForIP(ip string, limit int) ([]EventEntry, error)` — newest-first, filtered by IP

These are used by the `status history` and `status ip` CLI subcommands to surface the audit trail without requiring a live daemon connection.

### External Blocklists

`internal/blocklist.Manager` fetches one or more plain-text IP/CIDR URLs on startup and then on a ticker. For each valid entry:

1. `store.BanRecord(ip, now+2×interval, ipv6)` — writes to bbolt with a self-healing expiry
2. `fwMgr.ApplyBan(ctx, site, ip, ipv6)` — pushes to UniFi

The 2× interval expiry ensures that bans auto-expire if the feed URL becomes permanently unreachable. IPs from blocklists go through the same idempotency check as CrowdSec decisions.

### Webhook Notifications

`internal/webhook.Notifier` posts a small JSON payload to a configured URL when named events are fired. The notifier is a no-op when the URL is empty or the event name is not in the allowed set. HTTP errors are logged at `warn` level and never propagate to the caller.

Circuit breaker state changes (`OnCircuitBreakerOpen` / `OnCircuitBreakerClose` callbacks on `ManagerConfig`) and reconcile drift are the three currently supported event types. The callbacks are plain `func()` values — the `firewall` package has no import dependency on `webhook`.

---

## Session Recovery

The UniFi controller may return `401 Unauthorized` when a session cookie expires or when the API key is rotated. The bouncer handles this with a mutex-guarded re-authentication mechanism:

1. Any goroutine that receives a 401 calls `sessionManager.EnsureAuth()`
2. The mutex ensures only one goroutine performs the re-authentication request
3. A `ReauthMinGap` timer prevents stampedes: if re-auth completed within the gap, subsequent callers skip it and assume the session is now valid
4. After successful re-auth, the failed request is retried once

This pattern prevents the thundering-herd problem when multiple goroutines encounter a 401 simultaneously.

---

## Batch Flushing

Updating a firewall group requires a `PUT` request with the full member list. Issuing one `PUT` per ban would be wasteful during ban waves.

Instead, `ApplyBan` / `ApplyUnban` accumulate IP changes in memory and mark the shard as `dirty`. After every CrowdSec decision batch, `SyncDirty` flushes all dirty shards: a single `PUT` with the full updated member list per shard. Failed flushes leave the shard dirty for retry at the next `SYNC_INTERVAL` tick.

New shards are created automatically when a shard reaches `FIREWALL_GROUP_CAPACITY`.

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

20 metrics under the `crowdsec_unifi_` namespace cover the full lifecycle:

- **Counters**: decisions processed/filtered, API calls, auth errors, reauth attempts, shard syncs, shards rebalanced
- **Histograms**: API call duration (per endpoint), reconcile duration (per trigger), decision latency (filter pipeline → successful UniFi write)
- **Gauges**: active bans (per site/family), firewall group size, DB size, dirty shards, last sync timestamp, shard IP count, shard occupancy ratio, circuit breaker state, reconcile delta

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

- **`internal/config`**: required field validation, defaults, `_FILE` injection, template syntax, zone pair parsing including port filter syntax (`src[:ports]->dst[:ports]`), out-of-range and non-numeric port validation, Cloudflare zone pair parsing
- **`internal/decision`**: filter pipeline (all 8 stages), IP parsing and sanitisation, private IP detection, whitelist matching, per-scenario duration overrides (`BLOCK_SCENARIO_DURATION_MAP`)
- **`internal/firewall`**: namer template rendering, shard manager operations, port TML creation and idempotency, `needsUpdateZonePolicy` including port TML ID comparison
- **`internal/controller`**: session management, 401 re-authentication logic, TML wire format conversion (PORT_NUMBER as int), port filter population in policy wire structs
- **`internal/storage`**: bbolt ban operations, group/policy cache, event ring buffer (record, list, list-by-IP, capacity eviction)
- **`internal/bouncer/handler`**: job handler idempotency, BAN_TTL cap, dry-run mode, per-site error continuation, auth error short-circuit, per-scenario zone routing (`ZONE_PAIRS_SCENARIO_MAP`) dispatching `ApplyBanWithZones`
- **`internal/bouncer/janitor`**: expired ban pruning, skip-on-unban-failure
- **`internal/logger`**: redaction patterns
- **`internal/lapi_metrics`**: Reporter construction, interval clamping, counter reset behaviour after push, payload structure validation, user-agent and API key headers, concurrent recording under the race detector, shutdown final-push
- **`internal/capabilities`**: Constant value contracts (`BouncerType`, `Layer`, remediation support flags) and the intentional distinction between `BouncerType` (used in the metrics payload `type` field) and the LAPI user-agent service token (`crowdsec-unifi-bouncer`, used in HTTP headers)
- **`internal/whitelist`**: TML creation and update idempotency, ALLOW policy creation with IP TML IDs and port TML IDs, no-op when current, delete+recreate triggered when port TML IDs change (portFilter constraint), orphan policy and TML sweep, policy ordering (whitelist ALLOW policies placed before block policies via the ordering API)
- **`internal/webhook`**: fires on registered events, skips unregistered events, ignores HTTP errors, empty URL disables notifier, payload is valid JSON
- **`internal/blocklist`**: fetch and apply valid IPs, skip invalid lines, parse CIDRs, handle server errors and timeouts

A `nopRecorder` no-op implementation of `MetricsRecorder` is used in handler tests
to keep them independent of the LAPI metrics reporter.

The race detector (`go test -race ./...`) is run in CI for all packages. Concurrent tests use real bbolt databases in `t.TempDir()`.

---

## Differences from Teifun2/cs-unifi-bouncer

| Feature | Teifun2 | cs-unifi-bouncer-pro |
|---------|---------|---------------------|
| State persistence | None | ACID bbolt (3 buckets) |
| Decision handling | Single-threaded | Inline synchronous handler per batch |
| Ban auto-expiry | No | Yes (TTL from CrowdSec + `BAN_TTL`) |
| Multi-site | No | Yes |
| Firewall mode | Legacy only | Auto / legacy / zone |
| Object naming | Hardcoded strings | Go templates |
| Prometheus metrics | None | 20 `crowdsec_unifi_*` metrics |
| Log redaction | None | `RedactWriter` (regex-based) |
| Dry-run mode | No | Yes |
| Startup reconcile | No | Yes |
| Error handling | `log.Fatal` | Typed errors + exponential backoff retry |
| Session recovery | None | Mutex-guarded re-auth with thundering-herd guard |
| IPv6 | Limited | Full dual-stack with separate shard managers |
| Seccomp profile | None | 78-syscall allowlist |
| Image signing | None | Cosign keyless OIDC + CycloneDX SBOM |
| Port filtering | No | Per-direction port TMLs for block and ALLOW policies |
| Cloudflare whitelist | No | ALLOW policies for Cloudflare IP ranges, weekly refresh |
| Circuit breaker | No | Three-state breaker with configurable threshold and cooldown |
| Validate / diagnose | No | CLI subcommands for CI config checks and connectivity probes |
