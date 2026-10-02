# Upgrading

## From 2.1.0 to 2.1.1

The health server now starts before the firewall infrastructure is loaded, so
`/healthz` answers within seconds of startup even on a large ban list.

`/readyz` returns 503 with the body `starting` until the first decision batch
from the LAPI has been processed. On a ban list of ~100k decisions that takes
several minutes, and while the LAPI is unreachable at startup it does not end.
`HEALTH_CHECK_LAPI=false` does not skip this wait; it still only controls
whether `/readyz` checks the LAPI afterwards. Anything that waits for `/readyz`
to return 200 after a restart needs a timeout that covers the first pull.

The Docker image and both compose files raise the healthcheck `start_period`
from 15s to 120s. A compose file or orchestrator that sets its own healthcheck
keeps its own values; copy the new one if you see the container restart or
report unhealthy during startup. The example Kubernetes Deployment adds a
`startupProbe` on `/healthz` and sets `progressDeadlineSeconds: 1200`; see
[Kubernetes](kubernetes/README.md#health-endpoints).

An empty `HEALTH_ADDR` is now rejected at startup.

`CLOUDFLARE_IPV4_URL` and `CLOUDFLARE_IPV6_URL` must now be `https://` URLs; an
`http://` URL fails startup. A fetched list is rejected, keeping the ranges
from the last successful sync, when it is empty, has more than 1000 entries,
or contains a range that is private, non-public, broader than a /12 (IPv4) or
broader than a /29 (IPv6).

A blocklist feed whose country filter rejects every entry now keeps its
previous bans and logs an error; before, it released all of them. A feed that
lists fewer than half of its previous entries is applied without pruning. See
[Blocklist import](CONFIGURATION.md#external-blocklists). New settings
`BLOCKLIST_MIN_PREFIX_V4` (default `8`) and `BLOCKLIST_MIN_PREFIX_V6` (default
`32`) set the shortest prefix accepted for a feed entry.

Kubernetes manifests, re-apply all of them:

- `secret.example.yaml` now defines a Secret and a ConfigMap. The Secret holds
  only `UNIFI_API_KEY`, `UNIFI_USERNAME`, `UNIFI_PASSWORD` and
  `CROWDSEC_LAPI_KEY`; the Deployment mounts it as files under
  `/run/secrets/cs-unifi-bouncer-pro` and sets the matching `*_FILE` variables
  instead of loading the Secret with `envFrom`. Everything else (`UNIFI_URL`,
  `CROWDSEC_LAPI_URL`, `ZONE_PAIRS`, and any setting you added to the Secret)
  moves to the ConfigMap, which the Deployment loads with `envFrom`. A
  Deployment applied without the new ConfigMap does not start.
- `networkpolicy.yaml` no longer allows ingress on the health port or from
  every source on the metrics port: metrics are reachable from the `monitoring`
  namespace only. Egress is limited to cluster DNS, one controller address and
  the CrowdSec LAPI pods. Edit the marked placeholders before applying, or the
  bouncer loses its controller or LAPI connection.
- The memory limit rises from 256Mi to 512Mi, above the 256 MiB cap on a LAPI
  resync response. The pod also gets the `RuntimeDefault` seccomp profile and
  no service account token.

systemd: copy the new `docs/systemd/cs-unifi-bouncer-pro.service` over the
installed unit and run `systemctl daemon-reload`.

- The unit now sets `HEALTH_ADDR=127.0.0.1:8081` and
  `METRICS_ADDR=127.0.0.1:9090`. A remote Prometheus that scraped the host
  stops reaching the metrics port; set `METRICS_ADDR` in the environment file
  to an address it can reach. The environment file overrides the unit.
- Added `UMask=0077`, `ProtectProc=invisible`, `ProcSubset=pid`,
  `ProtectKernelLogs=yes`, `ProtectClock=yes`, `ProtectHostname=yes` and
  `SystemCallArchitectures=native`. `ProtectProc` and `ProcSubset` need
  systemd 247; remove them on an older release.

Seccomp: if you run with a downloaded copy of `security/seccomp-unifi.json`,
download it again. `clone` is now allowed only without namespace flags and
`clone3` returns `ENOSYS`, so the runtime creates threads through `clone`. A
profile of your own that allows `clone3` keeps working.

`/readyz` caches its result for 5 seconds. A dependency that recovers is
reported ready up to 5 seconds later.

A webhook endpoint that answers with a redirect no longer receives the event:
the redirect is logged and not followed, so point `WEBHOOK_URL` at the final
URL. An `http://` `WEBHOOK_URL` logs a warning at startup.

## From 2.0 to 2.1

Building from source now requires Go 1.27.1 or newer.

AbuseIPDB list importing is opt-in. Set `ABUSEIPDB_LIST` to a report window to
enable it, then optionally set `ABUSEIPDB_COUNTRY_INCLUDE` or
`ABUSEIPDB_COUNTRY_EXCLUDE`. See the
[configuration reference](CONFIGURATION.md#abuseipdb-blocklist) for the
available windows, limits, and refresh behavior. Existing `BLOCKLIST_URLS`
continue to work independently, including when a generic feed and AbuseIPDB
use the same URL.

On startup, existing URL-based blocklist claim sources are migrated to opaque
keys while preserving their expiry. A complete AbuseIPDB refresh removes only
its own claims for entries no longer selected. If a response contains invalid
lines, valid entries are still applied, but old claims are not pruned that
round. Once `BAN_TTL` has elapsed since the last complete fetch, stale claims
are no longer extended and expire at their existing deadlines.

Feed logs now show only scheme and host, and new persisted claim keys contain
no URL path or query string. Log redaction also covers base64-encoded Bearer
tokens.

## From 1.x to 2.0

2.0 turns on secure defaults and rejects settings that 1.x ignored or accepted
silently. Most deployments need one or two lines added to `.env`. Read
[Before you upgrade](#before-you-upgrade) and [Action required](#action-required)
first; the rest describes behaviour that changes without any action.

### Before you upgrade

1. Back up the bouncer's database (`/data/bouncer.db` in the container, or the
   `DATA_DIR` you configured). 2.0 rewrites its cache keys on first start, and
   1.x cannot read them back. To roll back, restore the backup, or run
   `cs-unifi-bouncer-pro drain` with 2.0 first.
2. Run `cs-unifi-bouncer-pro validate` with the 2.0 image against your
   current environment. It checks the configuration without contacting the
   controller or the LAPI; only the `UNIFI_SITES` check against the
   controller and the zone-mode check for `FIREWALL_MODE=auto` wait until
   startup.

### Action required

These stop a working 1.x deployment from starting, or change what it connects to.

| Setting | 1.x | 2.0 | What to do |
|---|---|---|---|
| `CROWDSEC_LAPI_URL` with `http://` and a non-loopback host | warning | startup error | Set `CROWDSEC_LAPI_ALLOW_HTTP=true` if the LAPI is on a trusted local network (the default Compose setup, `http://crowdsec:8080`), or switch the LAPI to HTTPS |
| `CROWDSEC_LAPI_URL` default | `http://crowdsec:8080` | `https://crowdsec:8080` | If you never set it and your LAPI serves plain HTTP, set `CROWDSEC_LAPI_URL=http://crowdsec:8080` and `CROWDSEC_LAPI_ALLOW_HTTP=true` |
| `UNIFI_VERIFY_TLS` default | `false` | `true` | For a self-signed controller certificate, mount it and set `UNIFI_CA_CERT`, or set `UNIFI_VERIFY_TLS=false` (logs a warning) |
| `UNIFI_REQUIRE_HTTPS` default | `false` | `true` | An `http://` `UNIFI_URL` is refused; set `UNIFI_REQUIRE_HTTPS=false` to allow it |
| `ZONE_PAIRS_SCENARIO_MAP` | accepted, no effect | startup error | Remove it; per-scenario policies were never provisioned |
| `FIREWALL_MODE=zone` without `UNIFI_API_KEY` | accepted | startup error | Set `UNIFI_API_KEY`; a username and password can only manage legacy rules |
| `FIREWALL_MODE=auto` with a username and password on a zone-based site | fell back to legacy | startup error | Set `UNIFI_API_KEY`, or `FIREWALL_MODE=legacy` if legacy rules are still enforced on that site |
| `CLOUDFLARE_WHITELIST_ENABLED=true` in legacy mode or without `UNIFI_API_KEY` | accepted, no effect | startup error | Use zone mode with an API key, or disable the whitelist |

Kubernetes and custom seccomp setups:

- Re-apply `docs/kubernetes/networkpolicy.yaml`: controller egress now also
  allows TCP 8443, which a self-hosted Network Application uses.
- `docs/kubernetes/secret.example.yaml` now uses `https://` for the LAPI. An
  existing secret with an `http://` URL needs `CROWDSEC_LAPI_ALLOW_HTTP: "true"`.
- If you run with a downloaded copy of `security/seccomp-unifi.json`, download
  it again: 2.0 needs the `mkdirat` syscall.

### Settings now checked at startup

1.x accepted these and misbehaved later; 2.0 stops with an error naming the
setting.

- `UNIFI_URL` and `CROWDSEC_LAPI_URL` must be absolute URLs with a host and
  without a username or password in them.
- `UNIFI_SITES` must list at least one site unless `UNIFI_SITES_AUTO=true`.
  Each site is checked against the controller, and the error lists the
  available sites (use the short name from the controller URL, such as
  `default`). With auto-discovery, a `UNIFI_SITES_EXCLUDE` that removes every
  site is an error.
- `METRICS_ADDR` and `HEALTH_ADDR` must differ when metrics are enabled.
- Durations and counts must be usable: `CROWDSEC_POLL_INTERVAL`,
  `SHUTDOWN_GRACE_PERIOD`, `UNIFI_HTTP_TIMEOUT`, `SESSION_REAUTH_TIMEOUT` and
  `CIRCUIT_BREAKER_RESET_INTERVAL` must be positive;
  `CIRCUIT_BREAKER_THRESHOLD` at least 1; `FIREWALL_API_SHARD_DELAY`,
  `FIREWALL_RECONCILE_INTERVAL` and `SESSION_REAUTH_MIN_GAP` not negative;
  `DECISION_BURST_SIZE` at least 1 when `DECISION_RATE_LIMIT` is set;
  `CROWDSEC_RESYNC_INTERVAL` 0 or at least 5m.
- `FIREWALL_GROUP_CAPACITY`, `_V4` and `_V6` must be between 1 and 10000, or 0
  for the default.
- `GROUP_NAME_TEMPLATE`, `RULE_NAME_TEMPLATE` and `POLICY_NAME_TEMPLATE` must
  render and include `{{.Index}}`. `{{.Prefix}}` (always empty in 1.x) is no
  longer a field.
- `ZONE_PAIRS` and `CLOUDFLARE_ZONE_PAIRS`: each entry needs exactly one `->`,
  zone names cannot contain commas, `@` needs at least one IP, and an empty
  entry (a stray `;`) is an error.
- `BLOCK_SCENARIO_DURATION_MAP` entries must be `scenario=duration` with a
  positive duration; 1.x skipped malformed entries.
- `BLOCKLIST_URLS`, `WEBHOOK_URL`, `CLOUDFLARE_IPV4_URL` and
  `CLOUDFLARE_IPV6_URL` must be absolute http(s) URLs,
  `BLOCKLIST_REFRESH_INTERVAL` must be positive when feeds are set, and
  `WEBHOOK_EVENTS` accepts only `circuit_breaker_open`,
  `circuit_breaker_close` and `reconcile_drift`.
- `FIREWALL_CONNECTION_STATES` (new) must be `ALL` or a list of `NEW`,
  `INVALID` and `ESTABLISHED`.

Removed settings: `FIREWALL_FLUSH_CONCURRENCY` logs a warning and has no
effect; `BLOCKLIST_NAME_PREFIX` is ignored. Remove both.

### Behaviour that changes without action

- **Zone block policies match new and invalid connections only**
  (`FIREWALL_CONNECTION_STATES=NEW,INVALID`). 1.x matched all connection
  states, so an established connection from a newly banned address was cut.
  Existing policies are updated on first start. Set
  `FIREWALL_CONNECTION_STATES=ALL` for the 1.x behaviour.
- **Reconcile runs every 10 minutes** (`FIREWALL_RECONCILE_INTERVAL`, was
  off). It restores managed groups and policies edited out of band, so
  addresses added by hand to a `crowdsec-*` group are removed.
- **`/readyz` checks the LAPI** (`HEALTH_CHECK_LAPI=true`, was `false`) with
  an authenticated request, so a wrong `CROWDSEC_LAPI_KEY` makes it return
  503.
- **Active decisions are re-read every hour** (`CROWDSEC_RESYNC_INTERVAL`) to
  recover bans the stream missed. Set 0 to disable.
- **Single-address ranges** (`x/32`, `x/128`) are stored and sent as bare
  addresses, which UniFi accepts. Bans stored as host prefixes are rekeyed once
  on first start, with a warning that includes the count (`rekeyed bans stored
  as /32 or /128 host prefixes…`). Those bans were not enforced by 1.x.
- **Stored bans are cleaned up at startup**: whitelisted, private and overly
  broad bans are lifted. Ranges broader than `/8` (IPv4) or `/32` (IPv6) are
  never banned, and whitelist and private checks now catch overlapping ranges.
- **Blocklist feeds**:
  - A failed fetch, or a 200 with no valid entries, keeps the feed's bans until
    `BAN_TTL` has passed since its last good fetch.
  - Feed entries now go through `BLOCK_WHITELIST` and the private-range checks.
  - Lines with an inline `#` or `;` comment are read (Spamhaus DROP).
  - A feed is capped at 16 MiB and 250,000 entries, and redirects are limited
    to 3, never to plain HTTP or to private or loopback addresses.
- **Durations**: a `BLOCK_SCENARIO_DURATION_MAP` override is no longer capped
  by `BAN_TTL`; the longest matching key wins; both `,` and `;` separate
  entries. `ban --duration 0` now bans for `BAN_TTL` instead of permanently,
  and longer durations are capped at `BAN_TTL`.
- **Unbans** from CrowdSec skip the ban-time filters, so a ban applied before a
  filter change can still be lifted.
- **`healthcheck`** reads only `HEALTH_ADDR`, so it works on systemd hosts
  without the full environment.
- **Metrics**: `crowdsec_unifi_decision_queue_depth` (never set) is removed;
  `crowdsec_unifi_unsynced_ips` and `crowdsec_unifi_shard_create_failures_total`
  are new.
- **Logs**: duration fields are strings such as `"1m0s"` instead of numbers,
  feed and webhook URLs are redacted, and CrowdSec client messages carry
  `"component":"crowdsec-client"`.
