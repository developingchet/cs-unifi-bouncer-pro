# Troubleshooting

Common issues and solutions for cs-unifi-bouncer-pro.

Most startup failures are printed to stderr as a single line starting with `error:` before the bouncer exits; everything else is a JSON log line. The image has no shell, so commands that need one (`curl`, `grep` on files) run on the host or in a helper container that shares the bouncer's network:

```bash
docker run --rm --network container:cs-unifi-bouncer-pro curlimages/curl -sv -o /dev/null http://crowdsec:8080/
```

`diagnose` checks the configuration, the LAPI, the controller and the UniFi Network version in one run:

```bash
docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro diagnose --lapi-auth
```

## Table of Contents

- [Container Won't Start](#container-wont-start)
  - [Configuration validation error](#configuration-validation-error)
  - [LAPI connection refused at startup](#lapi-connection-refused-at-startup)
  - [`/readyz` returns `starting` for several minutes](#readyz-returns-starting-for-several-minutes)
  - [UniFi controller unreachable at startup](#unifi-controller-unreachable-at-startup)
  - [Connection timeout to the UniFi controller (TCP stall on IPv6)](#connection-timeout-to-the-unifi-controller-tcp-stall-on-ipv6)
  - [Storage fails to open on first start](#storage-fails-to-open-on-first-start)
    - [`permission denied` — volume ownership wrong](#permission-denied--volume-ownership-wrong)
    - [`operation not permitted` — seccomp blocked a storage syscall](#operation-not-permitted--seccomp-blocked-a-storage-syscall)
  - [Seccomp profile blocks container startup](#seccomp-profile-blocks-container-startup)
- [No Bans Being Applied](#no-bans-being-applied)
  - [No decisions in CrowdSec](#no-decisions-in-crowdsec)
  - [Some decisions are listed in CrowdSec but never banned](#some-decisions-are-listed-in-crowdsec-but-never-banned)
  - [CrowdSec decision resync failed](#crowdsec-decision-resync-failed)
  - [Decisions are being filtered](#decisions-are-being-filtered)
  - [My own address is banned](#my-own-address-is-banned)
- [Authentication Errors](#authentication-errors)
  - [UniFi controller returns 401](#unifi-controller-returns-401)
  - [UniFi login is rate limited](#unifi-login-is-rate-limited)
  - [CrowdSec LAPI returns 401 or 403](#crowdsec-lapi-returns-401-or-403)
- [Cloudflare Whitelist Issues](#cloudflare-whitelist-issues)
  - [Cloudflare ALLOW policies not created](#cloudflare-allow-policies-not-created)
  - [Cloudflare whitelist blocks legitimate traffic](#cloudflare-whitelist-blocks-legitimate-traffic)
  - [Port filter TML not applied to whitelist policy](#port-filter-tml-not-applied-to-whitelist-policy)
- [Firewall Objects Not Created](#firewall-objects-not-created)
  - [Wrong firewall mode detected](#wrong-firewall-mode-detected)
  - [Startup fails: "uses the zone-based firewall, which requires UNIFI_API_KEY"](#startup-fails-uses-the-zone-based-firewall-which-requires-unifi_api_key)
  - [Startup fails: "applies only the zone-based firewall"](#startup-fails-applies-only-the-zone-based-firewall)
  - [Log warns "could not read the UniFi Network version"](#log-warns-could-not-read-the-unifi-network-version)
  - [Login fails against a self-hosted controller](#login-fails-against-a-self-hosted-controller)
  - [Zone names do not match](#zone-names-do-not-match)
  - [Invalid port in ZONE_PAIRS or CLOUDFLARE_ZONE_PAIRS](#invalid-port-in-zone_pairs-or-cloudflare_zone_pairs)
- [State and Reconcile Issues](#state-and-reconcile-issues)
  - [IPs not removed on unban](#ips-not-removed-on-unban)
  - [Group edited in the UniFi UI](#group-edited-in-the-unifi-ui)
  - [Bans stop applying after the controller restarts](#bans-stop-applying-after-the-controller-restarts)
  - [Stale policies after removing a zone pair](#stale-policies-after-removing-a-zone-pair)
  - [Duplicate firewall groups after rename](#duplicate-firewall-groups-after-rename)
  - [Log warns that objects exist that the database has no record of](#log-warns-that-objects-exist-that-the-database-has-no-record-of)
  - [The bouncer exits with "firewall mode changed"](#the-bouncer-exits-with-firewall-mode-changed)
  - [Policies named like legacy rules after a controller upgrade](#policies-named-like-legacy-rules-after-a-controller-upgrade)
  - [Log warns that an ALLOW policy is evaluated before an egress block policy](#log-warns-that-an-allow-policy-is-evaluated-before-an-egress-block-policy)
- [Sync Issues](#sync-issues)
  - [Shard sync failures](#shard-sync-failures)
  - [A range ban for one host stopped all syncing](#a-range-ban-for-one-host-stopped-all-syncing)
  - [Circuit breaker open — syncing stopped](#circuit-breaker-open--syncing-stopped)
- [Network Connectivity](#network-connectivity)
- [External Blocklist Issues](#external-blocklist-issues)
  - [Blocklist bans not being applied](#blocklist-bans-not-being-applied)
  - [AbuseIPDB list is missing or has fewer bans than expected](#abuseipdb-list-is-missing-or-has-fewer-bans-than-expected)
- [Webhook Issues](#webhook-issues)
  - [Webhook not firing](#webhook-not-firing)
- [Debug Procedure](#debug-procedure)

---

## Container Won't Start

### Configuration validation error

**Symptom:** The container exits immediately, and `docker logs` shows a configuration error:

```
error: load config: UNIFI_URL is required
```

**Cause:** A required environment variable is missing or a value is invalid. The first problem found is reported; fix it and start again to see the next one.

**Fix:** Verify the required variables are set in `.env`:

```bash
# Show the values Compose passes to the container
docker compose config | grep -E "UNIFI_URL|CROWDSEC_LAPI_URL|CROWDSEC_LAPI_KEY|UNIFI_API_KEY"

# Check for missing required fields
grep -E "^(UNIFI_URL|CROWDSEC_LAPI_URL|CROWDSEC_LAPI_KEY)=" .env
```

All three must be set and non-empty, along with either `UNIFI_API_KEY` or `UNIFI_USERNAME`/`UNIFI_PASSWORD`. `UNIFI_URL` and `CROWDSEC_LAPI_URL` must include a scheme (`http://` or `https://`) and must not contain a username or password; set `UNIFI_USERNAME`/`UNIFI_PASSWORD` instead.

Other settings checked at startup:

- `GROUP_NAME_TEMPLATE`, `RULE_NAME_TEMPLATE` and `POLICY_NAME_TEMPLATE` must render a non-empty name that includes `{{.Index}}`, using only `.Family`, `.Index`, `.Site`, `.SrcZone` and `.DstZone`.
- `WEBHOOK_EVENTS` accepts only the event names listed in [Webhook Notifications](CONFIGURATION.md#supported-event-names).
- `ZONE_PAIRS`, `EGRESS_ZONE_PAIRS` and `CLOUDFLARE_ZONE_PAIRS` name each `src->dst` pair once per site. `ZONE_PAIRS names External->Internal more than once` means two entries share their zones; merge them into one entry with all the ports (`External->Internal:80,443`).
- `UNIFI_CA_CERT: cannot read /certs/ca.pem: ...` (or `CROWDSEC_LAPI_CA_CERT`) means the path is wrong or the file is not mounted into the container.
- `METRICS_ADDR "0.0.0.0:8081" and HEALTH_ADDR ":8081" listen on the same port` means the two endpoints would compete for one socket; give them different ports.
- Removed settings such as `ZONE_PAIRS_SCENARIO_MAP` are refused; see [Removed and Renamed Settings](CONFIGURATION.md#removed-and-renamed-settings).

`validate` runs the same checks without contacting anything:

```bash
docker compose run --rm --no-deps cs-unifi-bouncer-pro validate
```

---

### LAPI connection refused at startup

**Symptom:** The bouncer keeps running, `/readyz` stays at `starting`, and the log repeats every 10 seconds:

```json
{"level":"error","component":"crowdsec-client","msg":"failed to connect to LAPI, retrying in 10s: ... connect: connection refused"}
```

**Cause:** `CROWDSEC_LAPI_URL` is unreachable from inside the container.

**Fix:**

1. Verify `CROWDSEC_LAPI_URL` is set correctly and reachable:
   - If CrowdSec is a Docker service on the same compose file, use its service name: `http://crowdsec:8080`
   - If CrowdSec is on the Docker host, use the host IP: `http://192.168.1.100:8080` (or `http://host.docker.internal:8080` on Docker Desktop)
   - If CrowdSec is on a different host, use its IP or hostname
2. Test connectivity from the bouncer's network namespace:
   ```bash
   docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro diagnose
   ```
   The `lapi_reachable` row shows the error. Without `--lapi-auth` it checks reachability only, not the key.

---

### `/readyz` returns `starting` for several minutes

**Symptom:** `docker ps` shows the container as `healthy`, but `curl http://localhost:8081/readyz` returns 503 with the body `starting`; a Kubernetes pod stays `0/1 Ready`.

**Cause:** `/readyz` stays unready until the first decision batch from the LAPI has been processed. On a ban list of ~100k decisions that pull takes several minutes. Docker's `HEALTHCHECK` probes `/healthz`, which answers as soon as the health server starts, so the container is healthy meanwhile. `HEALTH_CHECK_LAPI=false` does not skip this wait.

**Fix:** None needed while the pull is in progress; `startup stream batch synced to UniFi` in the logs marks the end. If that line never appears, the LAPI is unreachable or rejecting the key: see [LAPI connection refused at startup](#lapi-connection-refused-at-startup) and [CrowdSec LAPI returns 401 or 403](#crowdsec-lapi-returns-401-or-403).

---

### UniFi controller unreachable at startup

**Symptom:**

```
error: init UniFi client: probe controller at https://192.168.1.1: ... connect: connection refused
```

**Cause:** `UNIFI_URL` is wrong, the controller is down, or the container cannot reach it.

**Fix:**

1. Verify the URL is reachable from the host:
   ```bash
   curl -k https://192.168.1.1 -o /dev/null -w "%{http_code}"
   ```
2. `UNIFI_VERIFY_TLS` defaults to `true`. For a private controller certificate, provide its CA bundle via `UNIFI_CA_CERT`.

A controller that is still starting answers with an error status instead; the bouncer then exits with `controller at ... is not ready` and the restart policy retries it.

---

### Connection timeout to the UniFi controller (TCP stall on IPv6)

**Symptom:** Startup hangs and then fails after `UNIFI_HTTP_TIMEOUT`:

```
error: init UniFi client: probe controller at https://192.168.1.1: ... context deadline exceeded
```

**Cause:** With `UNIFI_DIAL_IPV6=true` (or its deprecated name `ENABLE_IPV6=true`) the HTTP client dials both IPv6 and IPv4 (happy eyeballs). When the host has IPv6 interfaces but no working IPv6 route to the controller, the IPv6 SYN stalls instead of being rejected, and each connection waits for it before falling back to IPv4.

**Fix:** Leave `UNIFI_DIAL_IPV6` at its default, `false`, and remove `ENABLE_IPV6`:

```bash
grep -E '^(UNIFI_DIAL_IPV6|ENABLE_IPV6)=' .env
# Should output nothing or "UNIFI_DIAL_IPV6=false"
```

If either is set to `true`, set `UNIFI_DIAL_IPV6=false`, delete the `ENABLE_IPV6` line and recreate the container:

```bash
docker compose up -d --force-recreate cs-unifi-bouncer-pro
```

`UNIFI_DIAL_IPV6` only controls how the bouncer dials the controller. `FIREWALL_ENABLE_IPV6`, which controls whether IPv6 bans are enforced, is independent of it.

To confirm the dial network, enable the request trace:

```bash
echo "UNIFI_API_DEBUG=true" >> .env
echo "LOG_LEVEL=debug" >> .env   # the trace is logged at debug level
docker compose up -d --force-recreate cs-unifi-bouncer-pro
docker logs cs-unifi-bouncer-pro 2>&1 | grep "httptrace: ConnectStart"
```

With `UNIFI_DIAL_IPV6=false` every line carries `"network":"tcp4"`; `tcp` means dual-stack dialing is on.

---

### Storage fails to open on first start

#### `permission denied` — volume ownership wrong

**Symptom:**

```
error: open storage: open bbolt at /data/bouncer.db (stop the running bouncer before offline commands): open /data/bouncer.db: permission denied
```

**Cause:** The container runs as UID 65532. A new named volume takes the ownership of `/data` from the image, but a bind mount, or a volume first created by another container, keeps its own ownership.

**Fix:** Find the exact volume name and chown it:

```bash
docker volume ls | grep bouncer
# use the full name from above (includes the compose project prefix):
docker run --rm -v <full-volume-name>:/data busybox chown -R 65532:65532 /data
docker compose up -d --force-recreate cs-unifi-bouncer-pro
```

For a bind mount, `chown -R 65532:65532` the host directory.

The same error, with a timeout instead of `permission denied`, means another process holds the database: an offline command (`reconcile`, `drain`, `ban`, `unban`) cannot run while the daemon is up.

#### `operation not permitted` — seccomp blocked a storage syscall

**Symptom:**

```
error: open storage: ... operation not permitted
```

or `create data dir: mkdir ...: operation not permitted`.

**Cause:** bbolt's storage layer (an mmap-based database) needs several syscalls beyond basic file I/O: `flock` (advisory locking), `fallocate` (pre-allocation), `madvise` (mmap hints) and `msync`/`fdatasync` (commit flush). Creating a `DATA_DIR` that does not exist yet also needs `mkdirat`. A seccomp profile that lacks one of them stops storage from opening.

**Fix:** Use `security/seccomp-unifi.json` from the release you run. If you maintain your own profile, make sure these syscalls are in the `SCMP_ACT_ALLOW` names array:

```json
"fallocate",
"fdatasync",
"flock",
"getrandom",
"madvise",
"mkdirat",
"msync",
"pwrite64",
"readv"
```

Then recreate the container so it picks up the profile:

```bash
docker compose up -d --force-recreate cs-unifi-bouncer-pro
```

---

### Seccomp profile blocks container startup

**Symptom:** Container crash-loops with:

```
error closing exec fds: readdirent fsmount:fscontext:proc/thread-self/fd/: operation not permitted
OCI runtime start failed [...] reopen exec fifo [...] operation not permitted
```

**Why this happens:** Docker's OCI runtime (`runc`) applies the seccomp filter before handing control to the Go binary. If any syscall runc uses during its init sequence is absent from the allowlist, the container crashes before the binary runs.

**Fix:** Ensure you are using the seccomp profile from the repository:

```bash
# Verify the profile file exists
ls -la ./security/seccomp-unifi.json

# Re-create the container (picks up the profile)
docker compose up -d --force-recreate cs-unifi-bouncer-pro
docker logs cs-unifi-bouncer-pro
```

If the problem persists on an older kernel, comment out the `seccomp` line in `docker-compose.yml` temporarily to isolate the cause.

---

## No Bans Being Applied

### No decisions in CrowdSec

**Symptom:** Bouncer starts successfully but no bans appear in UniFi.

**Check:**

```bash
docker exec crowdsec cscli decisions list
```

If no decisions are listed, the bouncer has nothing to process. Inject a test decision and look it up in the bouncer's database once the next sync has run:

```bash
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "test"
docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro status ip 203.0.113.42
```

Individual bans are not logged at the default `info` level; each shard write is (`shard flushed to UniFi`).

---

### Some decisions are listed in CrowdSec but never banned

**Symptom:** `cscli decisions list` shows a decision, it passes every filter,
but its IP is not in any shard. Often it is part of a bulk import
(`cscli decisions import`) where most of the import did arrive.

**Cause:** The LAPI stream returns decisions created after the bouncer's
previous poll. It stores `created_at` in whole seconds but keeps the poll
time with sub-second precision, so a decision created in the same second as a
poll is never streamed. A bouncer restart receives it, because the first poll
after a restart returns every active decision.

**Fix:** The bouncer re-reads every active decision each
`CROWDSEC_RESYNC_INTERVAL` (default `1h`) and applies the ones it has no
record of, logging `CrowdSec resync applied decisions the stream missed`.
Lower the interval (minimum `5m`) to recover them sooner, or restart the
bouncer.

---

### CrowdSec decision resync failed

**Symptom:** Every `CROWDSEC_RESYNC_INTERVAL` the log shows a warning:

```json
{"level":"warn","error":"decision list exceeds 64 MiB","msg":"CrowdSec decision resync failed"}
```

or the error `decode decision list: decision list has more than 500000
decisions`.

**Cause:** The resync reads every active decision from the LAPI and refuses a
response over 64 MiB or 500,000 decisions, which bounds the memory it needs.
Nothing from a refused response is applied. The decision stream is not
affected; only decisions the stream skipped are not recovered.

**Fix:** Reduce the number of active decisions, for example by subscribing to
fewer blocklists, or set `CROWDSEC_RESYNC_INTERVAL=0` to turn the resync off
and restart the bouncer when you need to recover skipped decisions. The error
`decode decision list: unexpected data after the decision list` means the LAPI
response was malformed; check what sits between the bouncer and the LAPI.

---

### Decisions are being filtered

**Symptom:** CrowdSec has active decisions but the bouncer does not apply them. Check which filter stage rejected them:

```bash
curl -s http://localhost:9090/metrics | grep crowdsec_unifi_decisions_filtered_total
```

Each rejected decision is also logged with a `filtered: ...` message. Parse failures are logged at `warn`; the other stages log at `trace`, so set `LOG_LEVEL=trace` temporarily to see them:

```bash
echo "LOG_LEVEL=trace" >> .env
docker compose up -d --force-recreate cs-unifi-bouncer-pro
docker logs -f cs-unifi-bouncer-pro 2>&1 | grep filtered
```

The `stage` label on the metric identifies which step rejected the decision:

| `stage` | Cause | Fix |
|---------|-------|-----|
| `1_action` | Decision type is neither `ban` nor `delete` (e.g. `captcha`) | Expected — only bans are enforced |
| `2_scenario_exclude` | Scenario matches `BLOCK_SCENARIO_EXCLUDE` | Expected — excluded scenarios are intentional |
| `3_origin` | Origin not in `CROWDSEC_ORIGINS` | Lower or remove `CROWDSEC_ORIGINS` |
| `4_scope` | Scope is not `ip` or `range` (e.g. ASN, country) | UniFi only accepts single IPs and CIDRs; this is a limitation |
| `5_parse` | Missing field, malformed IP address, or range broader than `/8` (IPv4) / `/32` (IPv6) | Indicates a bad decision in CrowdSec — check upstream |
| `6_private` | Private, reserved or CGNAT address | Expected — these addresses are never blocked |
| `7_whitelist` | IP is in `BLOCK_WHITELIST` | Expected — your trusted range |
| `8_min_duration` | Decision duration below `BLOCK_MIN_DURATION`, or not positive | Lower or remove `BLOCK_MIN_DURATION` |

Deletions are only checked by stages 1, 4 and 5, so a deletion still lifts a ban applied before `BLOCK_SCENARIO_EXCLUDE`, `CROWDSEC_ORIGINS` or `BLOCK_WHITELIST` was narrowed.

With `FIREWALL_ENABLE_IPV6=false`, IPv6 decisions pass the filter but are ignored without a log line.

---

### My own address is banned

**Symptom:** A trusted address (your WAN IP, an office range) is blocked in UniFi.

**Fix:** Add the address or range to `BLOCK_WHITELIST` and restart the bouncer. On startup, stored bans that `BLOCK_WHITELIST` now covers (as well as private addresses and ranges broader than `/8` IPv4 or `/32` IPv6) are deleted from the ban database, and a warning is logged:

```
lifted stored bans that are whitelisted, private or broader than /8 (IPv4) or /32 (IPv6); reconcile removes them from UniFi
```

The following reconcile removes them from the UniFi groups. New decisions for whitelisted addresses are rejected at stage `7_whitelist`.

---

## Authentication Errors

### UniFi controller returns 401

**Symptom:**

```json
{"level":"error","error":"unauthorized: HTTP 401","shard":"crowdsec-block-v4-0","msg":"shard sync failed, will retry next tick"}
```

**Cause:** The API key has been revoked, or the username/password credentials are wrong. With a username and password the bouncer logs in again once on a 401 and retries the request; an API key is sent unchanged.

**Fix:**

1. If using an API key: verify the key still exists in the UniFi console under **Settings → Control Plane → Integrations**
2. If using username/password: verify the credentials by logging into the UniFi console manually
3. Update `.env` with fresh credentials and restart:
   ```bash
   docker compose up -d --force-recreate cs-unifi-bouncer-pro
   ```

A site name that does not exist also draws a 401 from site-scoped requests.
Startup checks `UNIFI_SITES` against the controller first and stops with
`UNIFI_SITES: site "..." is not on the controller; available sites: ...`. Use
the short name from the controller URL (`/manage/<name>/...`), not the display name.

---

### UniFi login is rate limited

Applies to `UNIFI_USERNAME`/`UNIFI_PASSWORD`; an API key does not log in.

**Symptom:**

```json
{"level":"warn","error":"rate limited (retry after 1m0s)","consecutive_failures":1,"next_attempt_in":"1m0s","msg":"UniFi login failed"}
```

**Cause:** UniFi OS answers a login with HTTP 429 in two cases. More than five
successful logins in a minute (the bouncer and every CLI command it runs share
that allowance) clears within the minute. A few failed logins lock every
login out, the right password included, until the console has seen no login
attempts for well over ten minutes.

The bouncer cannot tell the two apart, so after consecutive 429s it waits 1,
2, 4, 8 and then 16 minutes before the next login. Syncs pause meanwhile and
resume on their own. A command that logs in, such as `unban` or `drain`, waits out one short
limit before giving up.

**Fix:**

1. If it follows an error-level `UniFi login failed` with `login ... returned
   HTTP 400`, `401` or `403`, the credentials are wrong. The bouncer backs off
   up to 30 minutes between such attempts. Correct the credentials and
   restart, then expect the first login to wait out the lockout.
2. Otherwise wait; avoid running several CLI commands in quick succession.

---

### CrowdSec LAPI returns 401 or 403

**Symptom:** `/readyz` stays at `starting` (or returns 503 later), and the `crowdsec-client` log lines report an authentication error from the LAPI.

**Cause:** The bouncer's LAPI key has been deleted from CrowdSec, or was never
registered. CrowdSec answers an unknown bouncer key with 403 Forbidden;
`diagnose --lapi-auth` reports both as `lapi_reachable FAIL ... check CROWDSEC_LAPI_KEY`.
Run it inside the bouncer's container (`docker exec`), so CrowdSec does not
record another `<bouncer>@<ip>` entry for the key.

**Fix:**

1. Check if the bouncer is registered:
   ```bash
   docker exec crowdsec cscli bouncers list
   ```
2. If `unifi-bouncer` is missing, re-register:
   ```bash
   docker exec crowdsec cscli bouncers add unifi-bouncer
   ```
3. Update `CROWDSEC_LAPI_KEY` in `.env` with the new key and restart.

---

## Cloudflare Whitelist Issues

### Cloudflare ALLOW policies not created

**Symptom:** `CLOUDFLARE_WHITELIST_ENABLED=true` is set but no ALLOW policies appear in UniFi.

**Check:**

```bash
docker logs cs-unifi-bouncer-pro 2>&1 | grep -i cloudflare
```

Failures are logged as `initial Cloudflare whitelist sync FAILED ...` at startup and `Cloudflare whitelist refresh failed` afterwards, with the cause in `error`:

| Error | Cause | Fix |
|-------|-------|-----|
| Startup error mentioning `UNIFI_API_KEY` or `FIREWALL_MODE=legacy` | The Cloudflare whitelist needs zone mode and an API key | Set `UNIFI_API_KEY` and leave `FIREWALL_MODE` at `auto` or `zone` |
| `CLOUDFLARE_WHITELIST_ENABLED is set but CLOUDFLARE_ZONE_PAIRS is empty` | `CLOUDFLARE_ZONE_PAIRS` not set | Set `CLOUDFLARE_ZONE_PAIRS=External->Internal` (or your zone names) |
| `resolve source zone "..."` or `resolve destination zone "..."` | Zone name in `CLOUDFLARE_ZONE_PAIRS` is wrong | Check the zone names in the UniFi console; zone names are case-sensitive |
| `fetch Cloudflare IPv4: ...` or `fetch Cloudflare IPv6: ...` | Cannot reach the Cloudflare IP list URL | Check outbound internet access from the container; verify `CLOUDFLARE_IPV4_URL` / `CLOUDFLARE_IPV6_URL` |

### Cloudflare whitelist blocks legitimate traffic

**Symptom:** Traffic from Cloudflare IPs is being dropped despite the whitelist being enabled.

**Cause:** Policies are evaluated in ascending index order, so an ALLOW policy must have a lower index than the block policies of its zone pair. The bouncer recreates its own block policies behind a newer ALLOW after each whitelist sync. If the log shows `cloudflare allow policy ... follows block ...`, the block is one it does not manage (or recreating it failed; the preceding warning says why).

**Fix:** Move or recreate a block policy you created yourself after the ALLOW. If the conflicting block is one of the bouncer's, fix the cause given in the `could not recreate every block policy` warning and restart the bouncer: the whitelist sync runs at startup and then every `CLOUDFLARE_REFRESH_INTERVAL`, and each run retries.

### Port filter TML not applied to whitelist policy

**Symptom:** Cloudflare ALLOW policies exist but do not have port filters as expected from `CLOUDFLARE_ZONE_PAIRS` port syntax (e.g. `External->Internal:80,443`).

**Check:**

```bash
docker logs cs-unifi-bouncer-pro 2>&1 | grep -E "ensure (source|destination) port TML"
```

`ensure source port TML for A->B: ...` or `ensure destination port TML for A->B: ...` means creating the port list failed; the rest of the error gives the controller's answer.

**Fix:** A failed port TML creation stops the whitelist sync for that site before its ALLOW policy is created. Correct the controller error; the next sync (or a restart) retries.

---

## Firewall Objects Not Created

### Wrong firewall mode detected

**Symptom:** Bans are applied to the wrong object type (legacy rules on a site that uses zones, or the reverse).

**Check:** The resolved mode is not logged. `diagnose` shows it per site in its `firewall_mode[site]` rows, and a zone-mode site logs `zone discovery complete` at startup:

```bash
docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro diagnose
```

**Fix:** Override the auto-detection by setting `FIREWALL_MODE=zone` or `FIREWALL_MODE=legacy` explicitly. On UniFi Network 11 and later only zone mode starts.

### Startup fails: "uses the zone-based firewall, which requires UNIFI_API_KEY"

**Cause:** The site has firewall zones, but the bouncer is logging in with `UNIFI_USERNAME`/`UNIFI_PASSWORD`. Zone policies can only be managed through the UniFi integration API, which does not accept username/password sessions.

**Fix:** Create an API key (**Settings → Control Plane → Integrations**) and set `UNIFI_API_KEY`. On UniFi Network 10.x and earlier, a site that still enforces legacy rules can keep username/password with `FIREWALL_MODE=legacy`. UniFi Network 11 and later apply only the zone-based firewall, so there an API key is the only option.

### Startup fails: "applies only the zone-based firewall"

**Cause:** The controller runs UniFi Network 11 or later, which moves every site to the zone-based firewall and ignores legacy `WAN_IN`/`WANv6_IN` rules. The bouncer refuses to create rules that would block nothing. There are two variants:

- `FIREWALL_MODE=legacy: UniFi Network 11.x applies only the zone-based firewall` — legacy mode was set explicitly.
- `site ... has no firewall zones, and UniFi Network 11.x applies only the zone-based firewall` — `FIREWALL_MODE=auto` found no zones: the controller returned none for the site, although Network 11 normally lists its system zones even before a gateway is adopted.

**Fix:** Set `UNIFI_API_KEY` and `ZONE_PAIRS`, and use `FIREWALL_MODE=auto` or `zone`. On a site with no gateway the policies are created but block nothing until a gateway is adopted; remove such a site from `UNIFI_SITES` if it never gets one. See [Upgrading the controller to UniFi Network 11](UPGRADING.md#upgrading-the-controller-to-unifi-network-11).

### Log warns "could not read the UniFi Network version"

**Cause:** The bouncer reads the version from the integration API (`/integration/v1/info`) with an API key, or from the site's `stat/sysinfo` with a username and password. The read failed or returned no version, so the bouncer starts as it would on a release that still applies legacy rules.

**Check:** `diagnose` shows the same error in its `unifi_version` row. A controller that is still starting answers 404 for a while; a restart once it is up clears the warning.

### Login fails against a self-hosted controller

**Symptom:** `login at /api/login returned HTTP 400` (or 401).

**Check:** The startup line `detected UniFi controller layout` shows `"layout":"standalone"` for the self-hosted Network Application and `"layout":"unifi-os"` for UniFi OS consoles. If the layout is right, the credentials are wrong: use a local admin account, not a UI.com cloud account, and make sure first-run setup has finished in the controller UI.

**Fix:** Correct `UNIFI_USERNAME`/`UNIFI_PASSWORD`. If the layout is wrong, check that `UNIFI_URL` points at the controller itself (e.g. `https://host:8443` for a self-hosted controller) and not at a reverse proxy that rewrites `/`.

---

### Zone names do not match

**Symptom:** Startup fails with:

```
error: load infrastructure: zone bootstrap for site default: cache zone "WAN" for site "default": zone "WAN" not found on this controller. Available zones: [External, Internal, Gateway, ...]. Zone names are case-sensitive — ...
```

When a zone differs only in case, the message adds `Did you mean "..." (check capitalisation)?`. Zone UUIDs are accepted in place of names.

**Cause:** `ZONE_PAIRS`, `EGRESS_ZONE_PAIRS` or `CLOUDFLARE_ZONE_PAIRS` names a zone that does not exist or is spelled differently on the controller.

**Fix:** Use a name from the `Available zones` list; names are case-sensitive:

```bash
ZONE_PAIRS=External->Internal
```

### Invalid port in ZONE_PAIRS or CLOUDFLARE_ZONE_PAIRS

**Symptom:** Bouncer exits at startup with a configuration error:

```
ZONE_PAIRS: invalid zone pair "External->Internal:0" dst: port 0 out of range (must be 1-65535)
```

**Cause:** A port number in the zone pair port list is `0`, above `65535`, non-numeric, or the port list after `:` is empty.

**Fix:** Correct the port list in `ZONE_PAIRS` or `CLOUDFLARE_ZONE_PAIRS`:

```bash
# Wrong — port 0 is invalid
ZONE_PAIRS=External->Internal:0,443

# Correct
ZONE_PAIRS=External->Internal:80,443
```

Use the `validate` subcommand to check configuration before deployment:

```bash
docker compose run --rm --no-deps cs-unifi-bouncer-pro validate
```

---

## State and Reconcile Issues

### IPs not removed on unban

**Symptom:** CrowdSec deletes a decision, but the IP remains blocked in UniFi.

**Check:**

```bash
# What the bouncer's database holds for the address
docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro status ip 203.0.113.42

# Force a reconcile; the running bouncer performs it
docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro reconcile
```

At `LOG_LEVEL=debug` each processed deletion logs `job applied` with `"action":"delete"`. An address stays banned while another source (a blocklist, a manual ban, a second CrowdSec decision) still claims it; `status ip` lists the claims.

The reconcile command compares the ban database with the current UniFi firewall state and removes any IPs not in the active ban list.

---

### Group edited in the UniFi UI

**Symptom:** Addresses were removed from (or added to) a `crowdsec-block-*` group by hand, and the change seems to stick.

**Behaviour:** Each periodic reconcile (`FIREWALL_RECONCILE_INTERVAL`) compares every managed group with the bouncer's own state and rewrites any group that differs, logging `shard changed outside the bouncer; rewriting it`. Edit bans through CrowdSec (`cscli decisions`) or the `ban`/`unban` subcommands instead; manual group edits are reverted.

### Bans stop applying after the controller restarts

A controller that is shutting down or starting answers every API call with HTTP 404, and a self-hosted controller can take several minutes to start. The bouncer confirms a 404 by listing the controller's groups before treating a group as deleted, so shards are kept and retried until the controller is ready (`shard write returned 404 but the object still exists; controller is likely restarting`). Decisions received during the outage are applied once writes succeed. If the bouncer itself starts while the controller is still starting, it exits with `controller ... is not ready` and your restart policy retries it.

---

### Stale policies after removing a zone pair

**Symptom:** After removing an entry from `ZONE_PAIRS`, `EGRESS_ZONE_PAIRS` or `CLOUDFLARE_ZONE_PAIRS` and restarting, the old block or ALLOW policies (and any associated port-filter Traffic Matching Lists) are still visible in the UniFi console.

**Behaviour:** Orphaned managed objects are deleted automatically; no manual cleanup is needed.

- **Block policies** (`ZONE_PAIRS`, `EGRESS_ZONE_PAIRS`): whenever the bouncer ensures its policies (at startup and on each periodic reconcile), policies recorded in the database for the site that the current configuration no longer produces are deleted from UniFi and from the database. A second pass over the controller's policies deletes unmatched `BLOCK` policies that carry the managed description and the static name prefix, so objects the database has no record of are removed too. Templates without a static prefix rely on the database record for ownership.
- **Legacy rules**: orphaned rules are deleted when they carry the managed description, the static name prefix or a database record, the configured block action, the managed ruleset and a non-empty source group. A rule with another action or ruleset, left by an earlier `FIREWALL_BLOCK_ACTION` or `LEGACY_RULESET_*`, is deleted when its shard's group is pruned or drained, provided its only source group is that group and it has the static name prefix or a database record.
- **Cloudflare ALLOW policies** (`CLOUDFLARE_ZONE_PAIRS`): at every Cloudflare sync, policies with the managed description and the `crowdsec-whitelist-cloudflare-` prefix that are no longer in `CLOUDFLARE_ZONE_PAIRS` are deleted. Only the policy each sync ensured is kept, so duplicates of the same name are removed as well. Setting `CLOUDFLARE_WHITELIST_ENABLED=false` deletes every Cloudflare whitelist policy and list at the next start.
- **Port-filter TMLs**: lists named `crowdsec-ports-src-*`, `crowdsec-ports-dst-*`, `crowdsec-whitelist-cloudflare-srcports-*` and `crowdsec-whitelist-cloudflare-dstports-*` that no longer correspond to a configured zone pair are deleted.

The cleanup requires ownership evidence from the database or a static name prefix along with the managed description and expected rule shape. Keep custom name templates distinct from names used for manual policies.

---

### Duplicate firewall groups after rename

**Symptom:** UniFi shows old and new firewall groups (e.g. `crowdsec-block-v4-0` and `crowdsec-prod-v4-0`) after changing `GROUP_NAME_TEMPLATE`.

**Cause:** The bouncer creates objects under the new name but does not delete objects under the old name.

**Fix:**

1. Delete the old firewall groups and rules manually from the UniFi console
2. Stop the daemon, run `docker compose run --rm --no-deps cs-unifi-bouncer-pro reconcile`, then restart with `docker compose up -d cs-unifi-bouncer-pro`

---

### Log warns that objects exist that the database has no record of

**Symptom:** At startup the log shows `controller objects named like this instance's own exist that its database has no record of`, listing names such as `crowdsec-block-v4-0`.

**Cause:** Firewall groups or lists whose names match this instance's `GROUP_NAME_TEMPLATE` exist on the controller, but the bouncer's database holds no record of them. Either the database volume was lost or replaced, or a second bouncer instance manages the same UniFi site with the same name templates.

**Fix:**

- After a lost database the warning is informational: the bouncer adopts the objects and reconciles them against the CrowdSec decisions. It appears once.
- With two instances on one site, each must use distinct `GROUP_NAME_TEMPLATE`, `RULE_NAME_TEMPLATE` and `POLICY_NAME_TEMPLATE` values (see [Object Naming Templates](CONFIGURATION.md#object-naming-templates)). Instances that share names adopt, rewrite and delete each other's groups, rules and policies. Set the templates before the second instance first starts; changing them later renames objects (see [Duplicate firewall groups after rename](#duplicate-firewall-groups-after-rename)).

### The bouncer exits with "firewall mode changed"

**Symptom:** `firewall mode changed; exiting so the bouncer restarts in the new mode`, with `site ... was loaded in legacy mode, but ...`, and the container restarts.

**Cause:** Each periodic reconcile re-checks the sites loaded in legacy mode. The bouncer exits when the controller now runs UniFi Network 11 or later, or when `FIREWALL_MODE=auto` now finds firewall zones on the site, because its shards and rules were built for legacy mode. This is expected once after the controller is upgraded.

**Fix:** None when the restart policy (`restart: unless-stopped`, `Restart=on-failure`, a Kubernetes Deployment) starts it again: the next start loads the site in zone mode. A bouncer started without a restart policy stays stopped; start it again by hand and add one. If startup then fails with "uses the zone-based firewall, which requires UNIFI_API_KEY" or "applies only the zone-based firewall", set `UNIFI_API_KEY` and `ZONE_PAIRS`. If the bouncer keeps exiting with the same message, the controller is answering differently between checks; run `diagnose` and include its output in a bug report.

### Policies named like legacy rules after a controller upgrade

**Symptom:** After the site moved to the zone-based firewall, zone policies named like the bouncer's legacy rules (`crowdsec-drop-v4-0`, ...) block the shard lists.

**Cause:** Moving a site to the zone-based firewall converts its legacy rules into zone policies. The bouncer treats a BLOCK or REJECT policy as one of its converted rules when its name is a legacy rule the database records, or starts with the `RULE_NAME_TEMPLATE` prefix, and it blocks one of the bouncer's shard lists.

**Fix:** None. On startup in zone mode, once the bouncer's own block policies (`crowdsec-policy-*`) cover a list, it deletes the converted policies that block it and logs `deleted zone policy converted from a legacy rule`. A converted policy whose list has no enabled block policy of the bouncer's yet is kept, with `keeping a zone policy converted from a legacy rule`, and retried on each periodic reconcile. Pruning and `drain` delete converted policies together with the list they block. Policies that block other lists, or that are named otherwise, are never touched.

### Log warns that an ALLOW policy is evaluated before an egress block policy

**Symptom:** `an ALLOW policy is evaluated before an egress block policy for the same zones; hosts it allows can still connect to banned addresses until the ALLOW is moved after the block`, with `allow` and `block` naming the two policies.

**Cause:** The controller evaluates policies in order. An ALLOW for an `EGRESS_ZONE_PAIRS` pair's zones that comes before the bouncer's egress block lets matching traffic out to banned addresses. Unlike a Cloudflare ALLOW, the bouncer cannot fix this by recreating its block, which would only move the block further back.

**Fix:** Move the ALLOW after the `crowdsec-policy-egress-*` policies in **Settings → Policy Table**, or narrow it so it no longer matches the traffic the egress pair should block. The warning is logged again only when the set of such ALLOW policies changes.

### Log warns that a site has no policy to enforce IPv6 bans

**Symptom:** At startup, after a SIGHUP reload, or from `validate`: `FIREWALL_ENABLE_IPV6 is on, but every ZONE_PAIRS pair of site "default" is limited to IPv4 destination addresses and the site has no EGRESS_ZONE_PAIRS pair, so if it uses the zone-based firewall it has no policy to enforce IPv6 bans`.

**Cause:** A pair with only IPv4 destination addresses (`@192.168.1.10`) gets no IPv6 block policy, because IPv6 traffic never reaches those addresses. When every pair a site uses is like that and the site has no `EGRESS_ZONE_PAIRS` pair, its IPv6 bans are still written to an IPv6 shard list, but no policy uses it. Each site is checked with its own pairs (see [Pairs for one site](CONFIGURATION.md#pairs-for-one-site)). A site that resolves to legacy mode blocks IPv6 through its `WANv6_IN` rule and can ignore the warning.

**Fix:** Set `FIREWALL_ENABLE_IPV6=false` if the protected hosts have no IPv6 addresses, or add a pair for the site, or an IPv6 destination, that IPv6 traffic can match.

---

## Sync Issues

### Shard sync failures

**Symptom:**

```json
{"level":"warn","error":"...","msg":"SyncDirty after decision block failed"}
```

usually preceded by an error-level `shard sync failed, will retry next tick` naming the shard.

**Cause:** One or more shards could not be written to the UniFi API after a decision batch.

**Fix:** This is usually transient. Dirty shards are retried at the next `SYNC_INTERVAL` tick (default `30s`). If the error is chronic:

- Check UniFi controller connectivity
- Increase `FIREWALL_API_SHARD_DELAY` to space out rule/policy creates and group deletes (group membership `PUT`s are not delayed)
- Review the `crowdsec_unifi_dirty_shards` and `crowdsec_unifi_shard_sync_total{result="error"}` metrics

---

### A range ban for one host stopped all syncing

**Symptom:** After a decision such as `cscli decisions add -r 203.0.113.9/32`
(or a blocklist line in that form), logs repeat
`bad request: ... "args":"203.0.113.9/32","msg":"api.err.FirewallGroupInvalidArgs"`,
the circuit breaker opens and no new bans reach UniFi.

**Cause:** UniFi firewall groups refuse single-host prefixes (`/32`, `/128`)
and accept only the bare address. Earlier versions stored the prefix, so every
write of that shard failed, and the failures opened the breaker for all shards.

**Fix:** Upgrade. Host prefixes are stored as the bare address, and bans saved
in the old form are rekeyed at startup (logged once as "rekeyed bans stored as
/32 or /128 host prefixes"). If the controller refuses any other entry and names
it in the error, that entry alone is left out of its shard, logged as
"controller refused a ban entry", and counted in
`crowdsec_unifi_unsynced_ips`; the rest of the shard is still written. The
entry is offered again after an hour (drift detection reports it missing and
the shard is rewritten), so a refusal that does not recur does not leave the ban
unenforced. A shard leaves out at most 10 entries at once; a controller that
refuses more fails the write instead ("controller refused more ban entries than
a shard leaves out"), since every entry is already a canonical address or
prefix and that many refusals point at the controller or the connection to it.

---

### Circuit breaker open — syncing stopped

**Symptom:** The `crowdsec_unifi_circuit_breaker_open` metric is 1 and no bans
are being pushed to UniFi. The log shows `circuit breaker opened: too many
consecutive sync failures`, then `SyncDirty skipped` with the error
`sync deferred: controller circuit breaker open` on each tick.

**Cause:** The bouncer has seen `CIRCUIT_BREAKER_THRESHOLD` (default: 5)
consecutive sync failures — typically due to the UniFi controller being
unreachable or returning 5xx errors. A controller that answers HTTP 400
(it refused the content of one shard) does not count toward the breaker.

**Resolution:**
1. Check UniFi controller health and network connectivity from the bouncer container.
2. After `CIRCUIT_BREAKER_RESET_INTERVAL` (default: 60s) one probe is let through;
   when it succeeds the breaker closes (`circuit breaker closed: controller reachable again`).
3. To recover immediately: restart the bouncer container.
4. To reduce sensitivity: increase `CIRCUIT_BREAKER_THRESHOLD` or
   `CIRCUIT_BREAKER_RESET_INTERVAL` in your environment.

---

## Network Connectivity

### Cannot reach UniFi controller

```bash
# Test from the host
curl -k https://192.168.1.1 -o /dev/null -w "HTTP %{http_code}\n"

# Test from the bouncer's network namespace, including the credentials
docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro diagnose
```

`unifi_reachable PASS` means the controller answered and the credentials were accepted. The built-in `healthcheck` subcommand only probes the bouncer's own `/healthz` and says nothing about the controller.

### Cannot reach CrowdSec LAPI

```bash
# Test from the host
curl http://localhost:8080/v1/decisions/stream?startup=true \
  -H "X-Api-Key: YOUR_LAPI_KEY" -o /dev/null -w "HTTP %{http_code}\n"
```

Expected: `200` (stream starts) or `403` (wrong key).

---

## External Blocklist Issues

### Blocklist bans not being applied

**Symptom:** `BLOCKLIST_URLS` is set but no bans from the feed appear.

**Check:**

```bash
docker logs cs-unifi-bouncer-pro 2>&1 | grep "blocklist:"
```

A failed fetch is logged as `blocklist: fetch failed` with the cause in `error`:

| Error | Cause | Fix |
|-------|-------|-----|
| `fetch: ... connection refused` | URL unreachable from container | Verify outbound internet access; check the URL manually with `curl` |
| `server returned 404` | URL returns non-200 | Verify the URL is correct |
| `no valid entries (N lines skipped)` | All lines are invalid or commented | Check the feed format (one IP or CIDR per line; text after `#` or `;` is a comment) |
| `blocklist exceeds ...` | The feed is over 16 MiB or 250,000 entries | Use a smaller feed |

Blocklist bans are applied on startup and then every `BLOCKLIST_REFRESH_INTERVAL`. To force an immediate refresh, restart the container.

### AbuseIPDB list is missing or has fewer bans than expected

Set `ABUSEIPDB_LIST` to one of the supported report windows; the country
settings alone do not enable the importer. Check its startup and refresh logs:

```bash
docker logs cs-unifi-bouncer-pro 2>&1 | grep -E "blocklist: (feed configured|fetch complete|fetch failed|feed applied without pruning)"
```

`entries` counts valid addresses retained after the country filter;
`filtered` counts valid addresses dropped by it. An include filter drops lines
without a two-letter country tag. An exclude filter is applied after include,
and the same code cannot appear in both. Lists `120d` and longer require an
include filter because an unfiltered list can exceed the 250,000-entry cap.

| Log message or error | Meaning | Action |
|----------------------|---------|--------|
| `country filter matched none of the N entries; previous bans kept` | The response was valid but no country tag passed the filter; the importer's existing bans are kept | Check `ABUSEIPDB_COUNTRY_INCLUDE` and `ABUSEIPDB_COUNTRY_EXCLUDE` |
| `blocklist: feed applied without pruning` | Some lines were invalid, or the list shrank sharply; valid matching entries were applied while existing bans were kept | Check the feed format or trusted mirror; the last complete fetch time is unchanged |
| `no valid entries` | The response supplied no valid entries, so existing bans are kept subject to `BAN_TTL` | Check the URL and response format |
| `blocklist exceeds` | The response exceeded its byte or entry cap | Use a narrower country include filter or a shorter list window |

`ABUSEIPDB_URL` can point to a trusted mirror. Logs deliberately show only its
scheme and host; they do not expose URL paths or query tokens. For feed
settings and limits, see [AbuseIPDB Blocklist](CONFIGURATION.md#abuseipdb-blocklist).

---

## Webhook Issues

### Webhook not firing

**Symptom:** `WEBHOOK_URL` and `WEBHOOK_EVENTS` are set but no POSTs are received.

**Check:**

```bash
docker logs cs-unifi-bouncer-pro 2>&1 | grep -E "webhook|circuit breaker"
```

Common causes:

| Log message | Cause | Fix |
|-------------|-------|-----|
| `webhook: delivery failed` (warn) | Network error or timeout | Verify the URL is reachable from the container; webhook errors are non-fatal |
| `webhook: server returned error status` (warn) | The endpoint answered 4xx or 5xx | Check the endpoint's own logs |
| `webhook: redirect not followed` (warn) | The endpoint answered with a 3xx; the bouncer never re-sends the payload to a redirect target | Set `WEBHOOK_URL` to the final URL, for example the `https://` form of an `http://` URL |
| `webhook: queue full, event dropped` (warn) | The endpoint is too slow; more than 64 events are waiting | Check the endpoint's response time |
| No log entries | `WEBHOOK_URL` is empty, the event is not listed in `WEBHOOK_EVENTS`, the event has not happened, or `DRY_RUN=true` | Set `WEBHOOK_URL`; add the event to `WEBHOOK_EVENTS` (or leave it empty for all events). `reconcile_drift` fires only when a periodic reconcile adds and removes 100 or more IPs in total; `shard_create_failed`, `ban_entry_refused` and `cloudflare_whitelist_sync_failed` repeat at most once an hour for the same shard, entry or sync |

Webhook POSTs use a 5 second timeout and are never retried. The bouncer continues normally if a webhook call fails.

---

## Debug Procedure

When something is not working and the cause is unclear, follow these steps in order.

### Test against a real controller without making changes

`DRY_RUN=true` is the safe way to validate configuration and observe decision
processing against a live UniFi endpoint. The bouncer will:

- Connect and authenticate to both UniFi and the CrowdSec LAPI
- Read existing firewall state (groups, rules/policies)
- Log the changes it *would* make, prefixed with `[DRY-RUN]`
- Refuse every UniFi API request other than `GET` and `HEAD` (the login is the only exception), and leave the ban database untouched

```bash
# Add DRY_RUN to your .env
echo "DRY_RUN=true" >> .env
docker compose up -d --force-recreate cs-unifi-bouncer-pro

# Inject a test decision and watch the logs
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "dry run test"
docker logs -f cs-unifi-bouncer-pro 2>&1 | grep -E "DRY-RUN|203.0.113.42"
```

Expected log lines (exact field order may vary):
```json
{"level":"info","site":"default","mode":"zone","msg":"[DRY-RUN] would ensure firewall rules or policies for all shards"}
{"level":"info","action":"ban","ip":"203.0.113.42","msg":"[DRY-RUN] would update ban"}
```

Nothing will appear in the UniFi firewall console. When you are satisfied,
remove `DRY_RUN=true` from `.env` and restart normally; the first poll after
the restart returns every active CrowdSec decision, and the bouncer applies them.

**1. Check container health:**

```bash
docker inspect --format='{{json .State}}' cs-unifi-bouncer-pro \
  | jq '{Status, Running, ExitCode, Health: .Health.Status}'
```

**2. Check logs for errors:**

```bash
docker logs cs-unifi-bouncer-pro 2>&1 | grep -E '^error:|"level":"error"'
docker logs cs-unifi-bouncer-pro 2>&1 | grep '"level":"warn"'
```

**3. Run the built-in checks:**

```bash
docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro diagnose --lapi-auth
```

**4. Enable debug logging:**

```bash
echo "LOG_LEVEL=debug" >> .env
docker compose up -d --force-recreate cs-unifi-bouncer-pro
docker logs -f cs-unifi-bouncer-pro
```

**5. Inject a test decision:**

```bash
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "debug test"
# At debug level, "job applied" appears within one poll, and "shard flushed to UniFi" within SYNC_INTERVAL
docker logs -f cs-unifi-bouncer-pro 2>&1 | grep -E "203.0.113.42|shard flushed"
```

**6. Check the bouncer version:**

```bash
docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro version
```

**7. Check CrowdSec sees the bouncer:**

```bash
docker exec crowdsec cscli bouncers list
```

The `last_pull` timestamp should be recent (updated every `CROWDSEC_POLL_INTERVAL`).

**8. Check Prometheus metrics:**

```bash
curl -s http://localhost:9090/metrics | grep crowdsec_unifi_decisions_filtered
```

The counters show how many decisions each filter stage rejected.

---

If the problem persists after following these steps, open an issue at https://github.com/developingchet/cs-unifi-bouncer-pro/issues and include:

- Output of `docker logs cs-unifi-bouncer-pro` (sanitise credentials and IPs)
- Output of `docker inspect cs-unifi-bouncer-pro` (sanitise credentials)
- Output of `diagnose`
- Output of `docker exec crowdsec cscli bouncers list`
- Your Docker and Docker Compose versions
- UniFi Network version (the `unifi_version` row of `diagnose`)
- The firewall mode you are using
- A description of expected vs. actual behaviour
