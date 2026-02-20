# Troubleshooting

Common issues and solutions for cs-unifi-bouncer-pro.

## Table of Contents

- [Container Won't Start](#container-wont-start)
  - [Configuration validation error](#configuration-validation-error)
  - [LAPI connection refused at startup](#lapi-connection-refused-at-startup)
  - [UniFi controller unreachable at startup](#unifi-controller-unreachable-at-startup)
  - [Volume permission denied](#volume-permission-denied)
  - [Seccomp profile blocks container startup](#seccomp-profile-blocks-container-startup)
- [No Bans Being Applied](#no-bans-being-applied)
  - [No decisions in CrowdSec](#no-decisions-in-crowdsec)
  - [Decisions are being filtered](#decisions-are-being-filtered)
- [Authentication Errors](#authentication-errors)
  - [UniFi controller returns 401](#unifi-controller-returns-401)
  - [CrowdSec LAPI returns 401](#crowdsec-lapi-returns-401)
- [Firewall Objects Not Created](#firewall-objects-not-created)
  - [Wrong firewall mode detected](#wrong-firewall-mode-detected)
  - [Zone names do not match](#zone-names-do-not-match)
- [State and Reconcile Issues](#state-and-reconcile-issues)
  - [IPs not removed on unban](#ips-not-removed-on-unban)
  - [Duplicate firewall groups after rename](#duplicate-firewall-groups-after-rename)
- [Performance Issues](#performance-issues)
  - [API rate gate triggered](#api-rate-gate-triggered)
  - [Worker queue full — jobs dropped](#worker-queue-full--jobs-dropped)
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

1. Verify `CROWDSEC_LAPI_URL=http://crowdsec:8080` (use the service name, not `localhost`)
2. Confirm the bouncer and CrowdSec are on the same Docker network:
   ```bash
   docker network inspect crowdsec_net | grep -A2 '"Name"'
   ```
3. Test connectivity from the bouncer container:
   ```bash
   docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro healthcheck
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
2. `UNIFI_VERIFY_TLS` defaults to `false` (most controllers use self-signed certs). If you have enabled it, either set it back to `false` or provide a valid CA bundle via `UNIFI_CA_CERT`.

---

### Volume permission denied

**Symptom:**

```json
{"level":"error","error":"open /data/bouncer.db: permission denied","msg":"fatal"}
```

**Cause:** The named volume was created with root ownership before the image embedded `/data` with UID 65532 ownership.

**Fix (one-time, only for volumes created before this was corrected):**

```bash
# Find the volume name (compose project prefix + "bouncer-data")
docker volume ls | grep bouncer-data

# Repair ownership — replace <volume-name> with the actual name
docker run --rm -v <volume-name>:/data alpine chown 65532:65532 /data

# Restart
docker compose up -d
```

Fresh installs do not require this fix.

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

## Firewall Objects Not Created

### Wrong firewall mode detected

**Symptom:** Bans are applied to wrong rule type (legacy rules appear on a modern controller, or vice versa).

**Check:**

```bash
docker logs cs-unifi-bouncer-pro | grep firewall_mode
```

The startup log line shows the detected or configured mode.

**Fix:** Override the auto-detection by setting `FIREWALL_MODE=zone` or `FIREWALL_MODE=legacy` explicitly.

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

---

## State and Reconcile Issues

### IPs not removed on unban

**Symptom:** CrowdSec deletes a decision, but the IP remains blocked in UniFi.

**Check:**

```bash
# Verify the unban was received
docker logs cs-unifi-bouncer-pro | grep '"action":"unban"'

# Force a reconcile
docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro reconcile
```

The reconcile command compares bbolt state with the current UniFi firewall state and removes any IPs not in the active ban list.

---

### Duplicate firewall groups after rename

**Symptom:** UniFi shows old and new firewall groups (e.g. `crowdsec-block-v4-0` and `crowdsec-prod-v4-0`) after changing `GROUP_NAME_TEMPLATE`.

**Cause:** The bouncer creates objects under the new name but does not delete objects under the old name.

**Fix:**

1. Delete the old firewall groups and rules manually from the UniFi console
2. Run `docker exec cs-unifi-bouncer-pro /cs-unifi-bouncer-pro reconcile` to rebuild under the new names

---

## Performance Issues

### API rate gate triggered

**Symptom:**

```json
{"level":"warn","msg":"rate gate closed","calls_in_window":120,"window":"1m"}
```

**Cause:** The bouncer made more than `RATELIMIT_MAX_CALLS` UniFi API calls within `RATELIMIT_WINDOW`. Jobs are retried with backoff.

**Fix:** This is normal during large startup ban waves. If it is chronic:

- Increase `RATELIMIT_MAX_CALLS` (check your UniFi controller's documented limits)
- Increase `FIREWALL_BATCH_WINDOW` to accumulate more changes per API call
- Increase `POOL_RETRY_BASE` to spread retries over a longer interval

---

### Worker queue full — jobs dropped

**Symptom:**

```json
{"level":"warn","msg":"job dropped","reason":"queue full","action":"ban","ip":"1.2.3.4"}
```

**Cause:** The worker pool cannot keep up with the rate of incoming decisions. The bounded job channel is full.

**Fix:**

- Increase `POOL_QUEUE_DEPTH` (default 4096) to absorb larger bursts
- Increase `POOL_WORKERS` (default 4) to process jobs faster
- Dropped jobs will be re-delivered by CrowdSec on the next stream reconnect (`CROWDSEC_POLL_INTERVAL`)

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

## Debug Procedure

When something is not working and the cause is unclear, follow these steps in order:

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
