# Configuration Reference

All configuration is provided through environment variables (or `_FILE` variants for secrets). Copy `.env.example` to `.env` and edit as needed.

Sensitive values support Docker secrets and Kubernetes secrets via the `_FILE` suffix: set the variable to the path of a file containing the secret, and the application reads and trims its contents at startup.

```bash
# Direct value
UNIFI_PASSWORD=mypassword

# Via file (Docker secrets / Kubernetes secrets)
UNIFI_PASSWORD_FILE=/run/secrets/unifi_password
```

---

## Table of Contents

- [UniFi Controller Connection](#unifi-controller-connection)
- [UniFi Sites](#unifi-sites)
- [Firewall Mode](#firewall-mode)
- [Object Naming Templates](#object-naming-templates)
- [Legacy Firewall Mode](#legacy-firewall-mode)
- [Zone-Based Firewall Mode](#zone-based-firewall-mode)
- [CrowdSec LAPI](#crowdsec-lapi)
- [Decision Filtering](#decision-filtering)
- [Worker Pool](#worker-pool)
- [API Rate Gate](#api-rate-gate)
- [Session Management](#session-management)
- [Storage](#storage)
- [Operational](#operational)

---

## UniFi Controller Connection

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `UNIFI_URL` | — | **Yes** | Controller URL including scheme, e.g. `https://192.168.1.1` or `https://unifi.local:8443` |
| `UNIFI_API_KEY` | — | One of API key or user/pass | UniFi API key. Takes precedence over username/password. `_FILE` variant supported. |
| `UNIFI_USERNAME` | — | One of API key or user/pass | Local admin username |
| `UNIFI_PASSWORD` | — | One of API key or user/pass | Local admin password. `_FILE` variant supported. |
| `UNIFI_VERIFY_TLS` | `false` | No | Verify the controller's TLS certificate. Set to `true` only when the controller has a valid CA-signed cert or `UNIFI_CA_CERT` is provided. |
| `UNIFI_CA_CERT` | — | No | Path to a PEM CA certificate for self-signed controller certs. |
| `UNIFI_HTTP_TIMEOUT` | `15s` | No | HTTP request timeout for UniFi API calls. |
| `UNIFI_API_DEBUG` | `false` | No | Log raw HTTP request/response bodies (verbose; do not use in production). |

### Authentication priority

API key authentication is preferred. If `UNIFI_API_KEY` is set, username/password fields are ignored. API key authentication is available in UniFi Network ≥ 8.1.

---

## UniFi Sites

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `UNIFI_SITES` | `default` | No | Comma-separated list of UniFi site names. Bans are applied to **all** listed sites simultaneously. |

Site names are the internal short names (visible in the URL when logged into the controller), not display names. The default site is named `default`.

```bash
# Single site (most deployments)
UNIFI_SITES=default

# Multiple sites
UNIFI_SITES=default,homelab,iot
```

---

## Firewall Mode

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `FIREWALL_MODE` | `auto` | No | `auto`, `legacy`, or `zone` |
| `FIREWALL_BLOCK_ACTION` | `drop` | No | Block action for legacy rules: `drop` or `reject` |
| `FIREWALL_ENABLE_IPV6` | `true` | No | Create separate IPv6 firewall groups and rules |
| `FIREWALL_GROUP_CAPACITY` | `10000` | No | Maximum IPs per firewall group shard |
| `FIREWALL_GROUP_CAPACITY_V4` | — | No | Override capacity for IPv4 groups |
| `FIREWALL_GROUP_CAPACITY_V6` | — | No | Override capacity for IPv6 groups |
| `FIREWALL_BATCH_WINDOW` | `500ms` | No | Accumulate group member changes for this duration before issuing a single API update |
| `FIREWALL_API_SHARD_DELAY` | `250ms` | No | Minimum pause between consecutive write calls (`PUT /rest/firewallgroup`, rule/policy `POST`/`DELETE`). Prevents the UDM from stacking back-to-back ruleset regenerations. Set `0` to disable. |
| `FIREWALL_FLUSH_CONCURRENCY` | `1` | No | Maximum concurrent `PUT /rest/firewallgroup` calls in-flight across all sites and address families. `1` = fully serialized (recommended). Increase only for multi-site setups where faster bulk updates are needed. |
| `FIREWALL_LOG_DROPS` | `false` | No | Enable UniFi "log dropped packets" on managed firewall rules |
| `FIREWALL_RECONCILE_ON_START` | `true` | No | Run a full reconcile on startup before accepting the CrowdSec stream |
| `FIREWALL_RECONCILE_INTERVAL` | — | No | Periodically re-sync UniFi state with bbolt (e.g. `6h`). `0` or empty = startup only. |

### Firewall mode details

**`auto`** (recommended): The bouncer queries the UniFi controller to detect whether zone-based firewall policies are supported. Controllers running UniFi Network ≥ 8.x use zone mode; older versions use legacy mode. The detected mode is logged at startup.

**`legacy`**: Creates `WAN_IN` and `WANv6_IN` drop rules that reference managed address-group shards. Works with all UniFi Network versions.

**`zone`**: Creates zone-based firewall policies for each pair in `ZONE_PAIRS`. Requires UniFi Network ≥ 8.x. Specify at least one zone pair.

### Group capacity and sharding

UniFi firewall groups have an upper limit on members. When the number of banned IPs exceeds `FIREWALL_GROUP_CAPACITY`, the bouncer automatically creates additional shards (e.g. `crowdsec-block-v4-0`, `crowdsec-block-v4-1`, ...) and creates matching rules or policies for each. The default of 10,000 is conservative; raise it if you observe frequent sharding.

---

## Object Naming Templates

The bouncer uses Go templates for all managed UniFi object names. This allows multiple bouncer instances to coexist without naming conflicts.

| Variable | Default | Description |
|----------|---------|-------------|
| `GROUP_NAME_TEMPLATE` | `crowdsec-block-{{.Family}}-{{.Index}}` | Name template for firewall address groups |
| `RULE_NAME_TEMPLATE` | `crowdsec-drop-{{.Family}}-{{.Index}}` | Name template for legacy firewall rules |
| `POLICY_NAME_TEMPLATE` | `crowdsec-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}` | Name template for zone firewall policies |
| `OBJECT_DESCRIPTION` | `Managed by cs-unifi-bouncer-pro. Do not edit manually.` | Description set on all managed objects |

### Template variables

| Variable | Type | Description |
|----------|------|-------------|
| `.Family` | string | `v4` or `v6` |
| `.Index` | int | Shard index, starting at `0` |
| `.Site` | string | UniFi site name |
| `.SrcZone` | string | Source zone name (zone mode only) |
| `.DstZone` | string | Destination zone name (zone mode only) |

### Multi-instance example

```bash
# Instance A (production)
GROUP_NAME_TEMPLATE=crowdsec-prod-{{.Family}}-{{.Index}}

# Instance B (staging)
GROUP_NAME_TEMPLATE=crowdsec-staging-{{.Family}}-{{.Index}}
```

**Warning**: Changing templates in a running deployment renames managed objects. The bouncer will recreate them with the new names and may lose track of objects created under the old names. Plan renames carefully.

---

## Legacy Firewall Mode

These settings apply only when `FIREWALL_MODE=legacy` or when `auto` detects a legacy controller.

| Variable | Default | Description |
|----------|---------|-------------|
| `LEGACY_RULE_INDEX_START_V4` | `22000` | Starting rule index for IPv4 drop rules (WAN_IN). Higher numbers = lower priority. |
| `LEGACY_RULE_INDEX_START_V6` | `27000` | Starting rule index for IPv6 drop rules (WANv6_IN). |
| `LEGACY_RULESET_V4` | `WAN_IN` | IPv4 ruleset to attach drop rules to |
| `LEGACY_RULESET_V6` | `WANv6_IN` | IPv6 ruleset to attach drop rules to |

Rules are indexed sequentially from the start value across shards: `22000`, `22001`, `22002`, ...

---

## Zone-Based Firewall Mode

These settings apply only when `FIREWALL_MODE=zone` or when `auto` detects a zone-capable controller.

| Variable | Default | Description |
|----------|---------|-------------|
| `ZONE_PAIRS` | `External->Internal` | Comma-separated `src->dst` zone pairs. A policy is created for each pair and each shard. `External` and `Internal` are the default zone names in UniFi Network 8.x — check Settings → Firewall → Zones if you have renamed them. |
| `ZONE_CONNECTION_STATES` | `new,invalid` | Connection states to match. Comma-separated. **Note: this value is accepted by the config parser but is not yet wired to the zone policy API payload. All connection states are matched by the policy regardless of this setting.** |
| `ZONE_POLICY_REORDER` | `true` | Move bouncer-managed policies to the highest priority in each zone pair. |

```bash
# Single pair (most common — default UniFi 8.x zone names)
ZONE_PAIRS=External->Internal

# Multiple pairs — block from WAN into all internal segments
ZONE_PAIRS=External->Internal,External->IoT,External->DMZ,External->VPN
```

Zone names must match the zone names configured in the UniFi controller exactly (case-sensitive).

---

## CrowdSec LAPI

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `CROWDSEC_LAPI_URL` | `http://crowdsec:8080` | No | URL of the CrowdSec Local API |
| `CROWDSEC_LAPI_KEY` | — | **Yes** | Bouncer API key generated by `cscli bouncers add`. `_FILE` variant supported. |
| `CROWDSEC_LAPI_VERIFY_TLS` | `true` | No | Verify the LAPI's TLS certificate |
| `CROWDSEC_ORIGINS` | — | No | Comma-separated allowed decision origins. Empty = all origins accepted. Example: `crowdsec,lists` |
| `CROWDSEC_POLL_INTERVAL` | `30s` | No | How often to poll the LAPI stream for new decisions |
| `LAPI_METRICS_PUSH_INTERVAL` | `30m` | No | Interval for pushing metrics to LAPI `/v1/usage-metrics`; `0` disables; minimum enforced value is `10m` |

---

## Decision Filtering

Decisions from CrowdSec pass through an 8-stage filter pipeline before being enqueued. Each stage that rejects a decision is recorded in the `crowdsec_unifi_decisions_filtered_total` metric.

| Variable | Default | Description |
|----------|---------|-------------|
| `BLOCK_SCENARIO_EXCLUDE` | — | Comma-separated scenario substrings to skip. Example: `impossible-travel,test` |
| `BLOCK_WHITELIST` | — | Comma-separated IP addresses or CIDR ranges that are never blocked. Example: `10.0.0.0/8,192.168.0.0/16` |
| `BLOCK_MIN_DURATION` | — | Ignore ban decisions shorter than this duration. Example: `1h`. Useful to filter out short test decisions. |

### Filter pipeline stages

| Stage | What it rejects |
|-------|----------------|
| `action` | Non-ban decisions (e.g. delete events) |
| `scenario-exclude` | Scenarios matching any `BLOCK_SCENARIO_EXCLUDE` substring |
| `origin` | Origins not in `CROWDSEC_ORIGINS` (when set) |
| `scope` | Non-IP/CIDR scopes (ASN, country, etc.) |
| `parse` | Invalid or malformed IP addresses |
| `private-ip` | RFC 1918, loopback, link-local, and ULA addresses |
| `whitelist` | IPs matching `BLOCK_WHITELIST` |
| `min-duration` | Decisions shorter than `BLOCK_MIN_DURATION` |

---

## Worker Pool

| Variable | Default | Description |
|----------|---------|-------------|
| `POOL_WORKERS` | `4` | Number of concurrent worker goroutines (1–64). Increase for high-throughput deployments. |
| `POOL_QUEUE_DEPTH` | `4096` | Bounded job queue depth. Jobs are dropped (and a metric recorded) when the queue is full. |
| `POOL_MAX_RETRIES` | `3` | Maximum retry attempts per job before it is dropped |
| `POOL_RETRY_BASE` | `1s` | Base delay for exponential backoff between retries |

Each worker independently handles the idempotency check, rate gate, UniFi API call, and bbolt persistence for each ban/unban job.

---

## API Rate Gate

The rate gate prevents the bouncer from overwhelming the UniFi API during large ban waves. It uses a sliding-window counter stored in bbolt.

| Variable | Default | Description |
|----------|---------|-------------|
| `RATELIMIT_WINDOW` | `1m` | Rolling time window for rate counting |
| `RATELIMIT_MAX_CALLS` | `120` | Maximum UniFi API calls allowed within the window |

Jobs that arrive when the gate is closed are requeued with retry logic.

---

## Session Management

| Variable | Default | Description |
|----------|---------|-------------|
| `SESSION_REAUTH_MIN_GAP` | `5s` | Minimum time between re-authentication attempts. Prevents thundering herd on 401 responses. |
| `SESSION_REAUTH_TIMEOUT` | `10s` | Timeout for re-authentication requests |

When the UniFi controller returns a 401 Unauthorized, only one goroutine performs re-authentication. Others wait for the mutex and skip re-auth if it was completed within `SESSION_REAUTH_MIN_GAP`.

---

## Storage

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_DIR` | `/data` | Directory for the bbolt database file (`bouncer.db`). Mount as a named Docker volume for persistence. |
| `BAN_TTL` | `168h` | Maximum age of a ban record in bbolt. Records older than this are pruned by the janitor even if CrowdSec has not sent a delete decision. Default is 7 days. |

The database contains four bbolt buckets:

| Bucket | Contents |
|--------|---------|
| `bans` | IP → BanEntry (recorded at, expires at, IPv6 flag) |
| `rate` | Sliding-window timestamps for the API rate gate |
| `groups` | Firewall group shard cache (UniFi ID, members, dirty flag) |
| `policies` | Zone policy / legacy rule cache |

---

## Operational

| Variable | Default | Description |
|----------|---------|-------------|
| `DRY_RUN` | `false` | Safe testing mode. The bouncer connects to both the UniFi controller and CrowdSec LAPI, reads all existing state, and logs every action it *would* take — but makes zero write requests (no `POST`, `PUT`, or `DELETE` to UniFi) and does not mutate bbolt state. Reads (`GET`) are still performed so the diff output is meaningful. Turning off dry run after a dry run session starts cleanly with no phantom bbolt entries. |
| `LOG_LEVEL` | `info` | Log verbosity: `trace`, `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `json` | Log format: `json` (structured, for Loki/Splunk) or `text` (human-readable) |
| `METRICS_ENABLED` | `true` | Enable the Prometheus metrics HTTP server |
| `METRICS_ADDR` | `:9090` | Address for the Prometheus metrics endpoint |
| `HEALTH_ADDR` | `:8081` | Address for health endpoints (`/healthz`, `/readyz`) |
| `JANITOR_INTERVAL` | `1h` | How often the background janitor prunes expired bans and rate entries, and updates database size metrics |
