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
- [Cloudflare Whitelist](#cloudflare-whitelist)
- [CrowdSec LAPI](#crowdsec-lapi)
- [Decision Filtering](#decision-filtering)
- [Session Management](#session-management)
- [Storage](#storage)
- [Ban History](#ban-history)
- [External Blocklists](#external-blocklists)
- [Webhook Notifications](#webhook-notifications)
- [Operational](#operational)

---

## UniFi Controller Connection

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `UNIFI_URL` | — | **Yes** | Controller URL including scheme, e.g. `https://192.168.1.1` or `https://unifi.local:8443` |
| `UNIFI_API_KEY` | — | One of API key or user/pass | UniFi API key. Takes precedence over username/password. `_FILE` variant supported. |
| `UNIFI_USERNAME` | — | One of API key or user/pass | Local admin username. `_FILE` variant supported. |
| `UNIFI_PASSWORD` | — | One of API key or user/pass | Local admin password. `_FILE` variant supported. |
| `UNIFI_VERIFY_TLS` | `false` | No | Verify the controller's TLS certificate. Set to `true` only when the controller has a valid CA-signed cert or `UNIFI_CA_CERT` is provided. |
| `UNIFI_CA_CERT` | — | No | Path to a PEM CA certificate for self-signed controller certs. |
| `UNIFI_HTTP_TIMEOUT` | `120s` | No | HTTP request timeout for UniFi API calls. |
| `UNIFI_API_DEBUG` | `false` | No | Log raw HTTP request/response bodies (verbose; do not use in production). |
| `ENABLE_IPV6` | `false` | No | Enable IPv6 dialing for the HTTP client. Set to `true` only if your controller is reachable over IPv6 with a working network path. This is separate from `FIREWALL_ENABLE_IPV6`. |

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
| `FIREWALL_ENABLE_IPV6` | `true` | No | Create separate IPv6 firewall groups and rules. Distinct from `ENABLE_IPV6` which controls HTTP client IPv6 dialing. |
| `FIREWALL_GROUP_CAPACITY` | `10000` | No | Maximum IPs per firewall group shard (used if family-specific overrides are not set) |
| `FIREWALL_GROUP_CAPACITY_V4` | — | No | Override capacity for IPv4 groups (takes precedence over `FIREWALL_GROUP_CAPACITY`) |
| `FIREWALL_GROUP_CAPACITY_V6` | — | No | Override capacity for IPv6 groups (takes precedence over `FIREWALL_GROUP_CAPACITY`) |
| `FIREWALL_API_SHARD_DELAY` | `250ms` | No | Minimum pause between consecutive write calls (`PUT /rest/firewallgroup`, rule/policy `POST`/`DELETE`). Prevents the UDM from stacking back-to-back ruleset regenerations. Set `0` to disable. |
| `FIREWALL_FLUSH_CONCURRENCY` | `1` | No | Maximum concurrent `PUT /rest/firewallgroup` calls in-flight across all sites and address families. `1` = fully serialized (recommended). Increase only for multi-site setups where faster bulk updates are needed. |
| `FIREWALL_LOG_DROPS` | `false` | No | Enable UniFi "log dropped packets" on managed firewall rules |
| `FIREWALL_RECONCILE_ON_START` | `true` | No | Run a full reconcile on startup before accepting the CrowdSec stream |
| `FIREWALL_RECONCILE_INTERVAL` | — | No | Periodically re-sync UniFi state with bbolt (e.g. `6h`). `0` or empty = startup only. |

### Traffic Matching List / Shard Management (Integration v1 / Zone Mode)

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SYNC_INTERVAL` | `30s` | No | Retry interval for dirty shard flushes that failed after a decision batch. Shards are also flushed immediately after every decision batch. Minimum: `5s`. |
| `SHARD_LIMIT` | `10000` | No | Maximum IPs per Traffic Matching List shard. When a shard is full, a new shard + zone policies are created automatically. UniFi integration v1 supports up to 10,000 items per TML. |

### Firewall mode details

**`auto`** (recommended): The bouncer queries the UniFi controller to detect whether zone-based firewall policies are supported. Controllers running UniFi Network ≥ 8.x use zone mode; older versions use legacy mode. The detected mode is logged at startup.

**`legacy`**: Creates `WAN_IN` and `WANv6_IN` drop rules that reference managed address-group shards. Works with all UniFi Network versions.

**`zone`**: Creates zone-based firewall policies for each pair in `ZONE_PAIRS`. Requires UniFi Network ≥ 8.x. Specify at least one zone pair.

### Group capacity and sharding

UniFi firewall groups (legacy mode) and Traffic Matching Lists (zone mode) have a maximum capacity of 10,000 items per shard. When the number of banned IPs exceeds the configured capacity, the bouncer automatically creates additional shards (e.g. `crowdsec-block-v4-0`, `crowdsec-block-v4-1`, ...) and creates matching rules or policies for each.

IPs are distributed across shards using **bin-packing**: each shard is filled to capacity before a new shard is created. This minimizes the number of shards and keeps the firewall configuration compact.

After every CrowdSec decision batch, all dirty shards are flushed to the UniFi API immediately (`SyncDirty`). If a flush fails (e.g. transient network error), the shard remains dirty and is retried at the next `SYNC_INTERVAL` tick. This means multiple IP changes within a single decision batch are merged into one PUT request per shard.

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
| `ZONE_PAIRS` | `External->Dmz` | Comma-separated zone pairs in `src[:sport,...]->dst[:dport,...][@dstIP,...]` format. A block policy is created for each pair and each shard. Zone names are auto-resolved to UUIDs at startup via the integration v1 API. `External` and `Internal` are the default zone names in UniFi Network 8.x — check Settings → Firewall → Zones if you have renamed them. Standard UUIDs (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) and MongoDB ObjectIDs (24-char hex) are also accepted and passed through without a lookup. Optional colon-separated port lists after a zone name restrict which source or destination ports the block policies match (empty = any port). Optional `@ip1,ip2,...` suffix on the destination side restricts the block policy to specific destination hosts or subnets (IPv4 or IPv6 CIDRs accepted; empty = any destination). |

```bash
# Named zones (auto-resolved at startup) — no port filter (any port)
ZONE_PAIRS=External->Internal

# Multiple pairs
ZONE_PAIRS=External->Internal,External->IoT

# Restrict block policies to specific destination ports only
ZONE_PAIRS=External->Internal:80,443

# Separate source and destination port filters
ZONE_PAIRS=External:81,8443->Internal:80,443

# Scope to a specific destination subnet (any port)
ZONE_PAIRS=External->Dmz@10.0.1.0/24

# Destination port + destination IP filter combined
ZONE_PAIRS=External->Internal:443@10.0.0.5,10.0.0.6

# Multiple pairs — second scoped to a destination subnet
ZONE_PAIRS=External->Dmz;External->Internal@10.0.0.0/24

# Pass through UUIDs directly (standard 8-4-4-4-12 format)
ZONE_PAIRS=aaaaaaaa-0000-4000-8000-aaaaaaaaaaaa->bbbbbbbb-0000-4000-8000-bbbbbbbbbbbb
```

Zone names are case-sensitive and must match the names shown in Settings → Firewall → Zones. If a zone name cannot be found at startup the bouncer exits with an error listing the available zones.

### Per-scenario zone routing

| Variable | Default | Description |
|----------|---------|-------------|
| `ZONE_PAIRS_SCENARIO_MAP` | — | Per-scenario zone pair overrides. Semicolon-separated `key=pairs` entries where `key` is matched as a substring of the CrowdSec scenario name and `pairs` uses the same `src[:sport,...]->dst[:dport,...]` format as `ZONE_PAIRS`. When a ban's scenario matches a key, the override pairs are used instead of the default `ZONE_PAIRS`. Example: `ssh-bf=External:22->Internal:22;http-probing=External->Internal:80,443` |

In Phase 1, the override zone pairs are logged with each matching ban for audit purposes; full per-scenario shard provisioning (separate firewall groups per scenario) is reserved for a future release.

### Port filtering for zone pairs

Both `ZONE_PAIRS` and `CLOUDFLARE_ZONE_PAIRS` support an optional port list appended to either zone name using a colon separator:

```
src[:sport1,sport2,...]->dst[:dport1,dport2,...]
```

When a port list is provided, the bouncer creates a separate PORTS Traffic Matching List for that direction and attaches it to the corresponding firewall policy as a port filter. Ports must be integers in the range 1–65535.

| Example | Effect |
|---------|--------|
| `External->Internal` | Match all ports (no filter) |
| `External->Internal:80,443` | Match only destination ports 80 and 443 |
| `External:81,8443->Internal` | Match only source ports 81 and 8443 |
| `External:81,8443->Internal:80,443` | Match source ports 81/8443 **and** destination ports 80/443 |

Port TMLs are named `crowdsec-ports-src-{Src}-{Dst}` and `crowdsec-ports-dst-{Src}-{Dst}` (block policies) or `crowdsec-whitelist-cloudflare-srcports-{Src}-{Dst}` and `crowdsec-whitelist-cloudflare-dstports-{Src}-{Dst}` (Cloudflare ALLOW policies). They are created or updated at startup alongside the zone cache.

### Destination IP filtering for zone pairs

An optional `@ip1,ip2,...` suffix on the **destination side** of a zone pair scopes the block policy to specific destination hosts or subnets:

```
src[:sport,...]->dst[:dport,...][@dstIP1,dstIP2,...]
```

`@` may only appear once per pair and must follow the optional port list. Each entry is an IPv4 or IPv6 address or CIDR (`10.0.0.5`, `10.0.1.0/24`, `2001:db8::/32`). An invalid IP or CIDR is rejected at startup.

| Example | Effect |
|---------|--------|
| `External->Dmz@10.0.1.0/24` | Block traffic destined for `10.0.1.0/24` only |
| `External->Internal:443@10.0.0.5` | Block only destination port 443 **and** destination host `10.0.0.5` |
| `External:80->Internal@10.0.0.0/24` | Match source port 80, block only traffic destined for `10.0.0.0/24` |
| `External->Dmz;External->Internal@10.0.0.0/24` | First pair unrestricted; second scoped to subnet |

IPv4 and IPv6 destination IPs are split into separate Traffic Matching Lists (`crowdsec-dstips-v4-{Src}-{Dst}` and `crowdsec-dstips-v6-{Src}-{Dst}`) and attached to the corresponding v4/v6 block policies at creation time. Because the UniFi PUT endpoint does not accept destination `trafficFilter` changes, any modification to destination IPs triggers a delete-and-recreate of the affected policies (same behaviour as port filter changes).

---

## Cloudflare Whitelist

When enabled, the bouncer periodically fetches current Cloudflare IP ranges and maintains ALLOW policies in UniFi so that Cloudflare traffic is never blocked by the CrowdSec block policies. ALLOW policies are created at startup (before block shard policies are created), ensuring they receive lower policy indices and are evaluated first.

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `CLOUDFLARE_WHITELIST_ENABLED` | `false` | No | Enable the Cloudflare IP whitelist sync. |
| `CLOUDFLARE_REFRESH_INTERVAL` | `168h` | No | How often to re-fetch Cloudflare IP ranges and update the IP TMLs (default: weekly). |
| `CLOUDFLARE_IPV4_URL` | `https://www.cloudflare.com/ips-v4` | No | URL to fetch the current Cloudflare IPv4 CIDR list. |
| `CLOUDFLARE_IPV6_URL` | `https://www.cloudflare.com/ips-v6` | No | URL to fetch the current Cloudflare IPv6 CIDR list. |
| `CLOUDFLARE_ZONE_PAIRS` | — | If enabled | Comma-separated zone pairs in `src[:sport,...]->dst[:dport,...][@dstIP1,dstIP2,...]` format. Required when `CLOUDFLARE_WHITELIST_ENABLED=true`. Determines which zone pair(s) the Cloudflare ALLOW policies are created for. Supports the same port filter and destination IP filter syntax as `ZONE_PAIRS`. |

```bash
# Minimal — ALLOW Cloudflare traffic from External to Internal on any port
CLOUDFLARE_WHITELIST_ENABLED=true
CLOUDFLARE_ZONE_PAIRS=External->Internal

# Restrict Cloudflare ALLOW policies to HTTP/HTTPS traffic only
CLOUDFLARE_ZONE_PAIRS=External->Internal:80,443

# Full control — restrict both source and destination ports
CLOUDFLARE_ZONE_PAIRS=External:80,443->Internal:8080,8443

# Scope ALLOW to a specific destination host (e.g. a reverse proxy at 10.0.5.251)
CLOUDFLARE_ZONE_PAIRS=External->Dmz:80,443@10.0.5.251

# Multiple zone pairs
CLOUDFLARE_ZONE_PAIRS=External->Internal,External->DMZ
```

The shared IPv4 and IPv6 source IP TMLs are named `crowdsec-whitelist-cloudflare-v4` and `crowdsec-whitelist-cloudflare-v6`. ALLOW policies are named `crowdsec-whitelist-cloudflare-External-{DstName}-v4` and `crowdsec-whitelist-cloudflare-External-{DstName}-v6`. When destination IP filtering is configured via `@IP`, per-pair destination IP TMLs are also created: `crowdsec-whitelist-cloudflare-dstips-{Src}-{Dst}-v4` and `crowdsec-whitelist-cloudflare-dstips-{Src}-{Dst}-v6`.

Zone names in `CLOUDFLARE_ZONE_PAIRS` are resolved independently of `ZONE_PAIRS` — they do not need to be the same pairs.

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
| `BLOCK_SCENARIO_DURATION_MAP` | — | Per-scenario ban duration overrides. Semicolon-separated `key=duration` pairs where `key` is matched as a substring of the scenario name. Overrides `BAN_TTL` for matching bans. Example: `ssh-bf=168h;http-probing=24h` |

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
| `groups` | Firewall group shard cache (UniFi ID, members, dirty flag) |
| `policies` | Zone policy / legacy rule cache |
| `events` | Ban audit trail ring buffer (see [Ban History](#ban-history)) |

---

## Ban History

The bouncer keeps an audit trail of every ban, unban, and expiry event in the `events` bbolt bucket using a ring buffer.

| Variable | Default | Description |
|----------|---------|-------------|
| `HISTORY_MAX_EVENTS` | `10000` | Maximum number of audit trail events retained in the ring buffer. Once the limit is reached, the oldest entry is dropped for each new entry written. Set to `0` to use the default. |

Events are written after each successful ban (`action=ban`), unban (`action=unban`), and janitor expiry (`action=expire`). Each event records: action, origin, scenario, IP address, and timestamp.

### Querying the audit trail

Use the `status` subcommands to inspect the running state:

```bash
# Show currently active bans (paginated, sortable)
cs-unifi-bouncer-pro status bans --top 20 --sort ip
cs-unifi-bouncer-pro status bans --expiring 1h    # expiring within 1h
cs-unifi-bouncer-pro status bans --expired         # already expired in bbolt

# Show details + history for a specific IP
cs-unifi-bouncer-pro status ip 198.51.100.1

# Show recent audit trail events
cs-unifi-bouncer-pro status history --limit 50
```

All `status` subcommands accept `--data-dir` to point at a non-default database directory.

---

## External Blocklists

The bouncer can periodically fetch plain-text IP/CIDR blocklists from external URLs and apply them as bans. This is useful for integrating threat intelligence feeds that are not distributed via the CrowdSec LAPI.

| Variable | Default | Description |
|----------|---------|-------------|
| `BLOCKLIST_URLS` | — | Comma-separated list of URLs to fetch. Each URL must return a plain-text list with one IP address or CIDR per line. Lines beginning with `#` and blank lines are ignored. |
| `BLOCKLIST_REFRESH_INTERVAL` | `24h` | How often to re-fetch and re-apply each URL. Bans applied from external blocklists have their expiry set to `now + 2×BLOCKLIST_REFRESH_INTERVAL`, so they auto-expire if the URL becomes unreachable. |
| `BLOCKLIST_NAME_PREFIX` | `ext-blocklist` | Scenario name prefix used when recording blocklist bans in the audit trail. |

```bash
# Fetch two external threat intelligence feeds every 12 hours
BLOCKLIST_URLS=https://example.com/badips.txt,https://example.net/threatlist.txt
BLOCKLIST_REFRESH_INTERVAL=12h
BLOCKLIST_NAME_PREFIX=ext-threatintel
```

Blocklist bans go through the same `BanRecord` + `ApplyBan` path as CrowdSec decisions and are therefore subject to the same idempotency checks. They are also recorded in the audit trail.

---

## Webhook Notifications

The bouncer can POST a JSON notification to a webhook URL when significant events occur.

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBHOOK_URL` | — | URL to POST notifications to. Leave empty to disable. |
| `WEBHOOK_EVENTS` | — | Comma-separated list of event names to send. If empty (and `WEBHOOK_URL` is set), no events are sent. |

### Supported event names

| Event | Fired when |
|-------|-----------|
| `circuit_breaker_open` | The circuit breaker opens after consecutive sync failures |
| `circuit_breaker_close` | The circuit breaker resets to closed after a successful probe |
| `reconcile_drift` | A periodic reconcile finds ≥ 100 IPs that were added or removed |

### Notification payload

```json
{
  "event": "circuit_breaker_open",
  "detail": "consecutive failures exceeded threshold",
  "timestamp": "2026-03-07T12:00:00Z"
}
```

Webhook errors are logged at `warn` level and never cause the bouncer to exit or retry. The HTTP timeout for webhook POSTs is 5 seconds.

```bash
# Fire a notification when the circuit breaker trips or resets
WEBHOOK_URL=https://hooks.example.com/bouncer-alerts
WEBHOOK_EVENTS=circuit_breaker_open,circuit_breaker_close,reconcile_drift
```

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
