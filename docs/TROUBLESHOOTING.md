# Troubleshooting

Common issues and solutions for cs-unifi-bouncer-pro.

## Table of Contents

- [Container Won't Start](#container-wont-start)
  - [Configuration validation error](#configuration-validation-error)
  - [LAPI connection refused at startup](#lapi-connection-refused-at-startup)
  - [UniFi controller unreachable at startup](#unifi-controller-unreachable-at-startup)
  - [Storage fails to open on first start](#storage-fails-to-open-on-first-start)
    - [`permission denied` — volume ownership wrong](#permission-denied--volume-ownership-wrong)
    - [`operation not permitted` — seccomp blocked `flock`](#operation-not-permitted--seccomp-blocked-flock)
  - [Seccomp profile blocks container startup](#seccomp-profile-blocks-container-startup)
- [No Bans Being Applied](#no-bans-being-applied)
  - [No decisions in CrowdSec](#no-decisions-in-crowdsec)
  - [Decisions are being filtered](#decisions-are-being-filtered)
- [Authentication Errors](#authentication-errors)
  - [UniFi controller returns 401](#unifi-controller-returns-401)
  - [CrowdSec LAPI returns 401](#crowdsec-lapi-returns-401)
- [Cloudflare Whitelist Issues](#cloudflare-whitelist-issues)
  - [Cloudflare ALLOW policies not created](#cloudflare-allow-policies-not-created)
  - [Cloudflare whitelist blocks legitimate traffic](#cloudflare-whitelist-blocks-legitimate-traffic)
  - [Port filter TML not applied to whitelist policy](#port-filter-tml-not-applied-to-whitelist-policy)
- [Firewall Objects Not Created](#firewall-objects-not-created)
  - [Wrong firewall mode detected](#wrong-firewall-mode-detected)
  - [Zone names do not match](#zone-names-do-not-match)
  - [Invalid port in ZONE_PAIRS or CLOUDFLARE_ZONE_PAIRS](#invalid-port-in-zone_pairs-or-cloudflare_zone_pairs)
- [State and Reconcile Issues](#state-and-reconcile-issues)
  - [IPs not removed on unban](#ips-not-removed-on-unban)
  - [Group edited in the UniFi UI](#group-edited-in-the-unifi-ui)
  - [Bans stop applying after the controller restarts](#bans-stop-applying-after-the-controller-restarts)
  - [Shard creation fails with "API returned empty ID"](#shard-creation-fails-with-api-returned-empty-id)
  - [Stale policies after removing a zone pair](#stale-policies-after-removing-a-zone-pair)
  - [Duplicate firewall groups after rename](#duplicate-firewall-groups-after-rename)
- [Performance Issues](#performance-issues)
  - [API rate gate triggered](#api-rate-gate-triggered)
  - [Worker queue full — jobs dropped](#worker-queue-full--jobs-dropped)
- [External Blocklist Issues](#external-blocklist-issues)
  - [Blocklist bans not being applied](#blocklist-bans-not-being-applied)
- [Webhook Issues](#webhook-issues)
  - [Webhook not firing](#webhook-not-firing)
- [Network Connectivity](#network-connectivity)
- [Debug Procedure](#debug-procedure)

---

## Container Won't Start

### Configuration validation error

**Symptom:** Container exits immediately with a configuration error.

```json
{"level":"error","error":"3 configuration error(s):\n  - UNIFI_URL is required\n  - CROWDSEC_LAPI_KEY is required","msg":"fatal"}
```

**Cause:** One or more required environment variables are missing or invalid.

**Fix:** Verify all required variables are set in `.env`:

```bash
# Verify .env is loaded
docker compose config | grep -E "UNIFI_URL|CROWDSEC_LAPI_KEY|UNIFI_API_KEY"

# Check for missing required fields
grep -E "^(UNIFI_URL|CROWDSEC_LAPI_URL|CROWDSEC_LAPI_KEY)=" .env
```

All three must be set and non-empty. `UNIFI_URL` and `CROWDSEC_LAPI_URL` must include a scheme (`http://` or `https://`).

---

### LAPI connection refused at startup

**Symptom:**

```json
{"level":"error","error":"dial tcp: connect: connection refused","msg":"bouncer init failed"}
```

**Cause:** The `CROWDSEC_LAPI_URL` is unreachable from inside the container.

**Fix:**

1. Verify `CROWDSEC_LAPI_URL` is set correctly and reachable:
   - If CrowdSec is a Docker service on the same compose file, use its service name: `http://crowdsec:8080`
   - If CrowdSec is on the Docker host, use host IP: `http://192.168.1.100:8080` (or `http://host.docker.internal:8080` on Docker Desktop)
   - If CrowdSec is on a different host, use its IP or hostname
2. Test connectivity from inside the bouncer container:
   ```bash
   docker exec cs-unifi-bouncer-pro sh -c 'curl -v http://your-crowdsec-url:8080/api/v1/decisions?ip=1.1.1.1'
   ```
   This will fail with a 401 (missing auth), but a successful connection proves reachability.
3. Check the bouncer logs:
   ```bash
   docker logs cs-unifi-bouncer-pro
   ```

---

### UniFi controller unreachable at startup

**Symptom:**

```json
{"level":"error","error":"dial tcp 192.168.1.1:443: connect: connection refused","msg":"controller ping failed"}
```

**Cause:** `UNIFI_URL` is wrong, the controller is down, or the container cannot reach it.

**Fix:**

1. Verify the URL is reachable from the host:
   ```bash
   curl -k https://192.168.1.1 -o /dev/null -w "%{http_code}"
   ```
2. `UNIFI_VERIFY_TLS` defaults to `true`. For a private controller certificate, provide its CA bundle via `UNIFI_CA_CERT`.

---

### Connection timeout to UniFi controller (TCP stall on IPv6)

**Symptom:** The bouncer attempts to connect but hangs indefinitely, or times out after `UNIFI_HTTP_TIMEOUT`:

```json
{"level":"error","error":"context deadline exceeded","msg":"controller ping failed"}
```

This is often accompanied by curl hangs from inside the container:

```bash
docker exec cs-unifi-bouncer-pro sh -c 'timeout 5 curl -v https://192.168.1.1'
# Times out after 5 seconds with no output after "TCP_NODELAY set"
```

**Cause:** This is usually caused by Go's happy eyeballs algorithm attempting an IPv6 TCP connection to the UniFi controller when the host has IPv6 network interfaces but no working IPv6 route to the controller. The IPv6 SYN silently stalls (not rejected, just unreachable), and Go waits for a long timeout before falling back to IPv4. This can take 20+ seconds per connection attempt.

**Fix:** Set `ENABLE_IPV6=false` in your `.env` (this is already the default):

```bash
# Verify ENABLE_IPV6 is not set to true
grep ENABLE_IPV6 .env
# Should output nothing or "ENABLE_IPV6=false"
```

If it is set to `true`, change it to `false`:

```bash
sed -i 's/ENABLE_IPV6=true/ENABLE_IPV6=false/' .env
docker compose up -d --force-recreate cs-unifi-bouncer-pro
```

**Important distinction:** `ENABLE_IPV6` controls whether the HTTP client uses IPv6 to reach the UniFi controller (connection dial behavior). This is separate from `FIREWALL_ENABLE_IPV6`, which controls whether IPv6 firewall rules are created in UniFi. These are independent settings.

To verify the fix, enable debug logging and watch for `tcp4` in the trace:

```bash
echo "UNIFI_API_DEBUG=true" >> .env
docker compose up -d --force-recreate cs-unifi-bouncer-pro
docker logs cs-unifi-bouncer-pro | grep -E "ConnectStart|tcp"
```

Expected output (with `ENABLE_IPV6=false`):

```
ConnectStart network=tcp4
ConnectDone
```

If you see `tcp` (dual-stack) or `tcp6` attempts, `ENABLE_IPV6` is incorrectly set to `true`.

---

### Storage fails to open on first start

Two distinct errors can appear when the container starts for the first time.
Both are fixed automatically in images built after the fix was released.

#### `permission denied` — volume ownership wrong

**Symptom:**

```json
{"level":"error","error":"open storage: open bbolt at /data/bouncer.db: open /data/bouncer.db: permission denied","msg":"fatal"}
```

The named volume was initialised with root ownership. The container runs as UID 65532 and cannot write to it.

**Fix** — find the exact volume name and chown it:

```bash
docker volume ls | grep bouncer
# use the full name from above (includes the compose project prefix):
docker run --rm -v <full-volume-name>:/data busybox chown -R 65532:65532 /data
docker compose up -d --force-recreate cs-unifi-bouncer-pro
```

#### `operation not permitted` — seccomp blocked a storage syscall

**Symptom:**

```json
{"level":"error","error":"open storage: operation not permitted","msg":"fatal"}
```

bbolt's storage layer (mmap-based database) requires several syscalls beyond basic
file I/O: `flock` (advisory locking), `fallocate` (pre-allocation), `madvise` (mmap hint),
`msync` (commit flush), and `getrandom` (TLS entropy for HTTPS connections).
Older versions of the seccomp profile were missing some of these.

**Fix** — pull the latest image which includes the corrected seccomp profile:

```bash
docker compose pull cs-unifi-bouncer-pro
docker compose up -d --force-recreate cs-unifi-bouncer-pro
```

If you are using a custom or pinned seccomp profile, ensure these syscalls are
present in the `SCMP_ACT_ALLOW` names array within `security/seccomp-unifi.json`:

```json
"fallocate",
"fdatasync",
"flock",
"getrandom",
"madvise",
"msync",
"pwrite64",
"readv"
```

Then rebuild your image:

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

If no decisions are listed, the bouncer has nothing to process. Inject a test decision:

```bash
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "test"
docker logs -f cs-unifi-bouncer-pro | grep 203.0.113.42
```

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

### Decisions are being filtered

**Symptom:** CrowdSec has active decisions but the bouncer does not apply them. Enable debug logging:

```bash
# Temporarily enable debug
echo "LOG_LEVEL=debug" >> .env
docker compose up -d --force-recreate cs-unifi-bouncer-pro
docker logs -f cs-unifi-bouncer-pro
```

Look for `"msg":"decision filtered"` lines. The `stage` field identifies which step rejected the decision:

| `stage` | Cause | Fix |
|---------|-------|-----|
| `action` | Decision action is `del` (delete event) | Normal — delete events are processed as unbans, not filtered |
| `scenario-exclude` | Scenario matches `BLOCK_SCENARIO_EXCLUDE` | Expected — excluded scenarios are intentional |
| `origin` | Origin not in `CROWDSEC_ORIGINS` | Lower or remove `CROWDSEC_ORIGINS` |
| `scope` | Scope is not `ip` or `range` (e.g. ASN, country) | UniFi only accepts single IPs and CIDRs; this is a limitation |
| `parse` | Malformed IP address | Indicates a bad decision in CrowdSec — check upstream |
| `private-ip` | Private/reserved IP range | Expected — private IPs are never blocked |
| `whitelist` | IP is in `BLOCK_WHITELIST` | Expected — your trusted range |
| `min-duration` | Decision duration below `BLOCK_MIN_DURATION` | Lower or remove `BLOCK_MIN_DURATION` |

---

## Authentication Errors

### UniFi controller returns 401

**Symptom:**

```json
{"level":"error","error":"unauthorized (401)","msg":"ban apply failed","ip":"203.0.113.42"}
```

**Cause:** The API key has been revoked, or the username/password credentials are wrong.

**Fix:**

1. If using API key: verify the key is still valid in the UniFi console under **Settings → Admins & Users → API Keys**
2. If using username/password: verify the credentials by logging into the UniFi console manually
3. Update `.env` with fresh credentials and restart:
   ```bash
   docker compose up -d --force-recreate cs-unifi-bouncer-pro
   ```

---

### CrowdSec LAPI returns 401

**Symptom:**

```json
{"level":"error","error":"unauthorized (401)","msg":"stream error"}
```

**Cause:** The bouncer's LAPI key has been deleted from CrowdSec.

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
docker logs cs-unifi-bouncer-pro | grep cloudflare
```

Common causes and fixes:

| Log message | Cause | Fix |
|-------------|-------|-----|
| Startup error mentioning `UNIFI_API_KEY` or `FIREWALL_MODE=legacy` | The Cloudflare whitelist needs zone mode and an API key | Set `UNIFI_API_KEY` and leave `FIREWALL_MODE` at `auto` or `zone` |
| `CLOUDFLARE_ZONE_PAIRS is empty` | `CLOUDFLARE_ZONE_PAIRS` not set | Set `CLOUDFLARE_ZONE_PAIRS=External->Internal` (or your zone names) |
| `resolve src zone ... not found` | Zone name in `CLOUDFLARE_ZONE_PAIRS` is wrong | Check zone names in Settings → Firewall → Zones; zone names are case-sensitive |
| `fetch Cloudflare IPv4: ...` | Cannot reach Cloudflare IP list URL | Check outbound internet access from the container; verify `CLOUDFLARE_IPV4_URL` |

### Cloudflare whitelist blocks legitimate traffic

**Symptom:** Traffic from Cloudflare IPs is being dropped despite the whitelist being enabled.

**Cause:** ALLOW policies must be created before block shard policies — they are evaluated in ascending index order. If the bouncer was redeployed without draining first, block policies may have lower indices than the ALLOW policies.

**Fix:**

```bash
# 1. Stop the daemon to release the bbolt lock, then drain managed objects
docker compose stop cs-unifi-bouncer-pro
docker compose run --rm --no-deps cs-unifi-bouncer-pro drain --force

# 2. Restart — ALLOW policies are created first (startup sync), then block shard policies
docker compose up -d cs-unifi-bouncer-pro
```

### Port filter TML not applied to whitelist policy

**Symptom:** Cloudflare ALLOW policies exist but do not have port filters as expected from `CLOUDFLARE_ZONE_PAIRS` port syntax (e.g. `External->Internal:80,443`).

**Check:**

```bash
docker logs cs-unifi-bouncer-pro | grep -E "cloudflare.*port|ensure.*port TML"
```

If you see `ensure src port TML failed` or `ensure dst port TML failed`, the port TML creation failed. Check for controller connectivity errors.

**Fix:** A failed port TML creation stops whitelist sync before an ALLOW policy is created. Correct the controller error and restart the bouncer to retry.

---

## Firewall Objects Not Created

### Wrong firewall mode detected

**Symptom:** Bans are applied to wrong rule type (legacy rules appear on a modern controller, or vice versa).

**Check:**

```bash
docker logs cs-unifi-bouncer-pro | grep firewall_mode
```

The startup log line shows the detected or configured mode.

**Fix:** Override the auto-detection by setting `FIREWALL_MODE=zone` or `FIREWALL_MODE=legacy` explicitly.

### Startup fails: "uses the zone-based firewall, which requires UNIFI_API_KEY"

**Cause:** The site has firewall zones, but the bouncer is logging in with `UNIFI_USERNAME`/`UNIFI_PASSWORD`. Zone policies can only be managed through the UniFi integration API, which does not accept username/password sessions.

**Fix:** Create an API key (**Settings → Control Plane → Integrations**) and set `UNIFI_API_KEY`. To keep username/password and use legacy WAN_IN rules instead, set `FIREWALL_MODE=legacy`.

### Login fails against a self-hosted controller

**Symptom:** `login at /api/login returned HTTP 400` (or 401).

**Check:** The startup line `detected UniFi controller layout` shows `"layout":"standalone"` for the self-hosted Network Application and `"layout":"unifi-os"` for UniFi OS consoles. If the layout is right, the credentials are wrong: use a local admin account, not a UI.com cloud account, and make sure first-run setup has finished in the controller UI.

**Fix:** Correct `UNIFI_USERNAME`/`UNIFI_PASSWORD`. If the layout is wrong, check that `UNIFI_URL` points at the controller itself (e.g. `https://host:8443` for a self-hosted controller) and not at a reverse proxy that rewrites `/`.

---

### Zone names do not match

**Symptom:** Zone-based policies are not created. Logs show:

```json
{"level":"error","error":"zone 'WAN' not found","msg":"ensure infrastructure failed"}
```

**Cause:** `ZONE_PAIRS` references zone names that do not exist or are spelled differently in the UniFi controller.

**Fix:**

1. In the UniFi console, go to **Settings → Firewall & Security → Zones**
2. Note the exact zone names (case-sensitive)
3. Update `ZONE_PAIRS` to match:
   ```bash
   ZONE_PAIRS=WAN->LAN    # Use the exact names from UniFi
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
docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro validate
```

---

## State and Reconcile Issues

### IPs not removed on unban

**Symptom:** CrowdSec deletes a decision, but the IP remains blocked in UniFi.

**Check:**

```bash
# Verify the unban was received
docker logs cs-unifi-bouncer-pro | grep '"action":"unban"'

# Force a reconcile
docker compose stop cs-unifi-bouncer-pro
docker compose run --rm --no-deps cs-unifi-bouncer-pro reconcile
docker compose up -d cs-unifi-bouncer-pro
```

The reconcile command compares bbolt state with the current UniFi firewall state and removes any IPs not in the active ban list.

---

### Group edited in the UniFi UI

**Symptom:** Addresses were removed from (or added to) a `crowdsec-block-*` group by hand, and the change seems to stick.

**Behaviour:** Each periodic reconcile (`FIREWALL_RECONCILE_INTERVAL`) compares every managed group with the bouncer's own state and rewrites any group that differs, logging `shard changed outside the bouncer; rewriting it`. Edit bans through CrowdSec (`cscli decisions`) or the `ban`/`unban` subcommands instead; manual group edits are reverted.

### Bans stop applying after the controller restarts

A controller that is shutting down or starting answers every API call with HTTP 404, and a self-hosted controller can take several minutes to start. The bouncer confirms a 404 by listing the controller's groups before treating a group as deleted, so shards are kept and retried until the controller is ready (`shard write returned 404 but the object still exists; controller is likely restarting`). Decisions received during the outage are applied once writes succeed. If the bouncer itself starts while the controller is still starting, it exits with `controller ... is not ready` and your restart policy retries it.

### Shard creation fails with "API returned empty ID"

**Symptom:** A create for a name that already exists, such as `crowdsec-block-v4-8`, fails on every sync; `/readyz` returns 503; `crowdsec_unifi_api_calls_total` counts failed creates; the number of IPs across the `crowdsec-block-*` groups is lower than the number of bans; some groups have no `crowdsec-policy-*` policy.

**Cause:** Releases up to v1.2.5 numbered a new shard by counting shards. Once a shard number was missing (for example `crowdsec-block-v4-1` deleted), the next shard reused a number that was already taken, the controller refused the duplicate name, and every ban that did not fit in the existing shards stayed unapplied. Policies were also numbered by position rather than by shard number, so groups past the gap could be left without a block policy.

**Fix:** Upgrade. A new shard now takes the number after the highest one in use. Every shard gets its policy by its real number. A create that is refused or answers without an ID adopts an existing object of that name. A shard whose policy or rule the controller refuses no longer stops the other shards from getting theirs; it is retried on every sync and its bans count in `crowdsec_unifi_unsynced_ips` until it is enforced. The first reconcile after the upgrade creates the missing policies and the overflow shard. No manual cleanup is needed.

Durations in log lines carry their unit (`"elapsed":"2.467s"`). Earlier releases logged a bare number of milliseconds, so `"elapsed":2467.3` on `periodic reconcile complete` means about 2.5 seconds, not 41 minutes.

---

### Stale policies after removing a zone pair

**Symptom:** After removing an entry from `ZONE_PAIRS` or `CLOUDFLARE_ZONE_PAIRS` and restarting, the old block or ALLOW policies (and any associated port-filter Traffic Matching Lists) remain visible in the UniFi console.

**Cause:** In versions before v1.1.2 the bouncer did not sweep for orphaned managed objects. Starting with v1.1.2, orphan cleanup runs automatically. v1.2.2 extends this with API-level sweeps that work even when the bbolt database has no record of the object.

- **Block policies** (`ZONE_PAIRS`): at every `EnsurePolicies` call, policies tracked in bbolt for the site but no longer produced by the current config are deleted from UniFi and removed from bbolt. An API-level pass also sweeps unmatched `BLOCK` policies with the managed description and static name prefix. Templates without a static prefix rely on the bbolt record for ownership.
- **Legacy rules**: `EnsureRules` sweeps orphaned rules with the managed description, static name prefix or matching bbolt record, configured block action, managed ruleset, and a non-empty source group.
- **Cloudflare ALLOW policies** (`CLOUDFLARE_ZONE_PAIRS`): at every Cloudflare sync, policies with the managed description and naming prefix (`crowdsec-whitelist-cloudflare-`) that are no longer in `CLOUDFLARE_ZONE_PAIRS` are deleted. Since v1.1.8, orphan detection is ID-based: only the exact policy returned by the ensure call is protected, so stale duplicate-named policies are also correctly removed. Since v1.2.2, setting `CLOUDFLARE_WHITELIST_ENABLED=false` automatically drains **all** Cloudflare whitelist policies and TMLs on startup — no manual cleanup needed when disabling the feature.
- **Port-filter TMLs** (both `ZONE_PAIRS` and `CLOUDFLARE_ZONE_PAIRS`): TMLs named `crowdsec-ports-src-*`, `crowdsec-ports-dst-*`, `crowdsec-whitelist-cloudflare-srcports-*`, and `crowdsec-whitelist-cloudflare-dstports-*` that no longer correspond to a configured zone pair are deleted.

The cleanup requires ownership evidence from the cache or a static name prefix along with the managed description and expected rule shape. Keep custom name templates distinct from names used for manual policies.

**Action (upgrade from < v1.1.2):** Restart the bouncer after upgrading. The orphan sweep runs at startup and will remove the stale objects automatically. No manual deletion is needed.

---

### Duplicate firewall groups after rename

**Symptom:** UniFi shows old and new firewall groups (e.g. `crowdsec-block-v4-0` and `crowdsec-prod-v4-0`) after changing `GROUP_NAME_TEMPLATE`.

**Cause:** The bouncer creates objects under the new name but does not delete objects under the old name.

**Fix:**

1. Delete the old firewall groups and rules manually from the UniFi console
2. Stop the daemon, run `docker compose run --rm --no-deps cs-unifi-bouncer-pro reconcile`, then restart with `docker compose up -d cs-unifi-bouncer-pro`

---

## Performance Issues

### Shard sync failures

**Symptom:**

```json
{"level":"warn","msg":"SyncDirty after decision block failed","error":"..."}
```

**Cause:** A transient error prevented one or more shards from being flushed to the UniFi API after a decision batch.

**Fix:** This is usually transient. The bouncer will retry dirty shards at the next `SYNC_INTERVAL` tick (default `30s`). If the error is chronic:

- Check UniFi controller connectivity
- Increase `FIREWALL_API_SHARD_DELAY` to reduce request rate
- Review `crowdsec_unifi_dirty_shards` and `crowdsec_unifi_shard_sync_total{result="error"}` metrics

---

### A range ban for one host stopped all syncing (before this release)

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
`crowdsec_unifi_unsynced_ips`; the rest of the shard is still written.

---

### Circuit breaker open — syncing stopped

**Symptom:** `crowdsec_unifi_circuit_breaker_open` metric is 1. No bans
are being pushed to UniFi. Logs show "SyncDirty skipped: circuit breaker open".

**Cause:** The bouncer has seen `CIRCUIT_BREAKER_THRESHOLD` (default: 5)
consecutive sync failures — typically due to the UniFi controller being
unreachable or returning 5xx errors. A controller that answers HTTP 400
(it refused the content of one shard) does not count toward the breaker.

**Resolution:**
1. Check UniFi controller health and network connectivity from the bouncer container.
2. The breaker resets automatically after `CIRCUIT_BREAKER_RESET_INTERVAL` (default: 60s)
   if the next probe succeeds.
3. To recover immediately: restart the bouncer container.
4. To reduce sensitivity: increase `CIRCUIT_BREAKER_THRESHOLD` or
   `CIRCUIT_BREAKER_RESET_INTERVAL` in your environment.

---

## Network Connectivity

### Cannot reach UniFi controller

```bash
# Test from the host
curl -k https://192.168.1.1 -o /dev/null -w "HTTP %{http_code}\n"

# Use the built-in healthcheck
docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro healthcheck
echo "Exit: $?"
```

Exit 0 means the controller is reachable and the credentials are valid.

### Cannot reach CrowdSec LAPI

```bash
# Test from the host
curl http://localhost:8080/v1/decisions/stream?startup=true \
  -H "X-Api-Key: YOUR_LAPI_KEY" -o /dev/null -w "HTTP %{http_code}\n"
```

Expected: `200` (stream starts) or `401` (wrong key).

---

## External Blocklist Issues

### Blocklist bans not being applied

**Symptom:** `BLOCKLIST_URLS` is set but no bans from the feed appear.

**Check:**

```bash
docker logs cs-unifi-bouncer-pro | grep -E "blocklist|ext-blocklist"
```

Common causes:

| Log message | Cause | Fix |
|-------------|-------|-----|
| `fetch ... connection refused` | URL unreachable from container | Verify outbound internet access; check the URL manually with `curl` |
| `unexpected status 404` | URL returns non-200 | Verify the URL is correct |
| `0 valid entries` | All lines are invalid or commented | Check the feed format (one IP or CIDR per line; `#` comments are skipped) |

Blocklist bans are applied on startup and then every `BLOCKLIST_REFRESH_INTERVAL`. To force an immediate refresh, restart the container.

---

## Webhook Issues

### Webhook not firing

**Symptom:** `WEBHOOK_URL` and `WEBHOOK_EVENTS` are set but no POSTs are received.

**Check:**

```bash
docker logs cs-unifi-bouncer-pro | grep -E "webhook|circuit_breaker"
```

Common causes:

| Log message | Cause | Fix |
|-------------|-------|-----|
| `webhook: skipping unregistered event` | Event name not in `WEBHOOK_EVENTS` | Add the event to `WEBHOOK_EVENTS` |
| `webhook: POST failed` (warn) | Network error or non-2xx response | Verify the URL is reachable from the container; webhook errors are non-fatal |
| No log entries | `WEBHOOK_URL` is empty | Set `WEBHOOK_URL` in your `.env` |

Webhook POSTs use a 5 second timeout and are never retried. The bouncer continues normally if a webhook call fails.

---

## Debug Procedure

When something is not working and the cause is unclear, follow these steps in order:

### Test against a real controller without making changes

`DRY_RUN=true` is the safe way to validate configuration and observe decision
processing against a live UniFi endpoint. The bouncer will:

- Connect and authenticate to both UniFi and CrowdSec LAPI
- Read existing firewall state (groups, rules/policies)
- Log every action it *would* perform, prefixed with `[DRY-RUN]`
- Make **zero write requests** to UniFi and **no changes to bbolt**

```bash
# Add DRY_RUN to your .env
echo "DRY_RUN=true" >> .env
docker compose up -d --force-recreate cs-unifi-bouncer-pro

# Inject a test decision and watch the logs
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "dry run test"
docker logs -f cs-unifi-bouncer-pro | grep -E "DRY-RUN|203.0.113.42"
```

Expected log lines (exact field order may vary):
```json
{"level":"info","site":"default","mode":"legacy","msg":"[DRY-RUN] would ensure legacy firewall rules for all shards"}
{"level":"info","site":"default","ip":"203.0.113.42","ipv6":false,"msg":"[DRY-RUN] would apply ban"}
{"level":"info","action":"ban","ip":"203.0.113.42","msg":"[DRY-RUN] would persist job to bbolt"}
```

Nothing will appear in the UniFi firewall console, and bbolt will contain zero
entries. When you are satisfied, remove `DRY_RUN=true` from `.env` and restart
normally — the daemon will start with a clean state and apply all active CrowdSec
decisions from scratch.

**1. Check container health:**

```bash
docker inspect --format='{{json .State}}' cs-unifi-bouncer-pro \
  | jq '{Status, Running, ExitCode, Health: .Health.Status}'
```

**2. Check logs for errors:**

```bash
docker logs cs-unifi-bouncer-pro 2>&1 | grep '"level":"error"'
docker logs cs-unifi-bouncer-pro 2>&1 | grep '"level":"warn"'
```

**3. Enable debug logging:**

```bash
echo "LOG_LEVEL=debug" >> .env
docker compose up -d --force-recreate cs-unifi-bouncer-pro
docker logs -f cs-unifi-bouncer-pro
```

**4. Inject a test decision:**

```bash
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "debug test"
# Watch for the decision within 30 seconds
docker logs -f cs-unifi-bouncer-pro | grep 203.0.113.42
```

**5. Run the healthcheck:**

```bash
docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro healthcheck
echo "Healthcheck exit: $?"
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

Gauge values show how many decisions were filtered at each stage.

---

If the problem persists after following these steps, open an issue at https://github.com/developingchet/cs-unifi-bouncer-pro/issues and include:

- Output of `docker logs cs-unifi-bouncer-pro` (sanitise credentials and IPs)
- Output of `docker inspect cs-unifi-bouncer-pro` (sanitise credentials)
- Output of `docker exec crowdsec cscli bouncers list`
- Your Docker and Docker Compose versions
- UniFi Network Application version
- The firewall mode you are using
- A description of expected vs. actual behaviour
