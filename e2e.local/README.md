# Live e2e suite

A manual suite, not run in CI: it needs Docker Desktop and takes several
minutes. Run output (logs, cookies, generated certificates, the kubeconfig,
`udm.env` and UDM snapshots) is gitignored by `e2e.local/.gitignore`. It runs
the bouncer, built from this checkout, against real services:

| Service    | Image                                            | Host port                           |
|------------|--------------------------------------------------|-------------------------------------|
| `unifi`    | `lscr.io/linuxserver/unifi-network-application`  | `127.0.0.1:18443` (UI and API)      |
| `unifi-db` | `mongo:7.0` (user created by `init-mongo.sh`)    | none                                |
| `crowdsec` | `crowdsecurity/crowdsec:v1.7.8` (LAPI, offline)  | none                                |
| `mock`     | `./mock` (blocklist feed and webhook sink)       | `127.0.0.1:18080`                   |
| `bouncer`  | built from `..` with the production flags (read-only, seccomp, cap_drop ALL) | `18081` health, `19090` metrics |

The compose project is `csue2e`. The bouncer is behind the `bouncer` profile, so
always use `docker compose --profile bouncer ...`.

## Requirements

- Docker Desktop running
- Git Bash (on Windows), `curl` and `node` on PATH
- About 2 GB RAM free. A cold UniFi start takes 1 to 5 minutes. A full run takes about 10 to 15 minutes.

## Running it

```bash
bash e2e.local/run.sh                  # full suite, tears the stack down afterwards
KEEP=1 bash e2e.local/run.sh           # leave the stack up for poking around
bash e2e.local/run.sh > run.log 2>&1   # it is long; tail -f run.log | grep -E 'FAIL|RESULT'
E2E_UNIFI_API_KEY=... bash e2e.local/run.sh   # also run step 14 (API-key auth)
```

The run ends with `RESULT: N passed, N failed, N skipped (UniFi Network <version>)`.
The exit code is non-zero if any check fails. The last known good result is
83 passed, 0 failed, 1 skipped. Step 14 is skipped unless a key is set.

Only one run may be active: `.run.pid` refuses a second one (exit 3). When you
stop a run, kill the whole `bash run.sh` process tree. A leftover run keeps
going and its final `down -v` destroys the stack of the next run. Do not edit
`run.sh` while a run is going, because bash reads the script as it runs.

Tear down by hand after `KEEP=1`:

```bash
cd e2e.local && docker compose --profile bouncer down -v --remove-orphans
```

### Settings matrix

`settings.sh` restarts the bouncer with one group of settings changed at a
time and checks each setting's effect on the controller, the LAPI, the
endpoints, the metrics (including `promtool` and a real Prometheus scrape) and
the logs. It needs a stack started with `up.sh` and rebuilds the bouncer image
first. Each case's container log is kept in `cases/<name>.log`.

```bash
bash e2e.local/up.sh                               # start the stack and leave it up
bash e2e.local/settings.sh                         # every section
bash e2e.local/settings.sh metrics breaker         # just these sections
bash e2e.local/try.sh 'has_ip v4 198.19.1.1'       # run lib.sh helpers by hand
```

Sections: `validation observability metrics firewall decisions sites
connection breaker extra interact webhooks`. `extra` covers the remaining
single settings, `interact` covers settings that affect each other (whitelist,
origins, IPv6 and duration settings against feeds and CrowdSec decisions) and
`webhooks` checks a hanging or failing receiver. The run ends with `SETTINGS RESULT: N passed, N failed,
N skipped`. Run it on a fresh stack (`down -v`, then `up.sh`): cases use fixed
addresses, and a decision the bouncer already applied logs nothing, records no
event and marks no shard dirty, so several checks cannot fire a second time.

### Deployment matrix

`deploy.sh` runs the deployment artifacts the repo ships against the stack, the
way a user would. It stops the e2e bouncer while each deployment runs, since
both would manage the same controller objects.

| Section | What runs |
|---|---|
| `compose` | `docker-compose.yml` with a user `.env` |
| `standalone` | `docker-compose.standalone.yml` |
| `k8s` | `docs/kubernetes/*` (secret, PVC, NetworkPolicy, Deployment) on k3s in a container |
| `systemd` | `docs/systemd` unit under systemd in a container |
| `published` | the published `:latest` image. Not run by default: v1.2.5 and earlier cannot log in to a self-hosted controller |

Every deployment must become ready, enforce a new ban, keep it across a restart
and stop cleanly. The Docker ones also check the hardening (read-only root,
dropped capabilities, seccomp, non-root user). The run ends with
`DEPLOY RESULT: N passed, N failed, N skipped`.

### API-key mode (step 14)

This stack cannot run it. The self-hosted Network Application has no page or
documented API for creating integration keys: Settings > Control Plane >
Integrations is supplied by UniFi OS (a console or UniFi OS Server), and the
standalone UI drops `control-plane/*` routes when no UniFi OS host injects
them. Its server has an `api_key` store, but nothing here writes to it.

Zone mode and the Cloudflare whitelist also need firewall zones, and the
controller has none without an adopted gateway
(`GET /v2/api/site/default/firewall/zone` returns `[]`). So even with a key,
`FIREWALL_MODE=auto` resolves to legacy here. Zone mode is covered by the unit
and fake-server tests in `internal/firewall` and `internal/testutil`. A live run
needs a UniFi OS console with a gateway, which this stack does not provide:
see the next section.

### Zone mode against a UniFi OS console (`udm.sh`)

`udm.sh` runs zone mode against a real console (a UDM or other UniFi OS
gateway). It writes to that controller, so it is opt-in and never part of
`run.sh`; run it only with the controller owner's agreement.

**Set up by hand before each run** (the script never creates, edits or deletes
zones or networks, and they can be removed afterwards):

| Zone | Network in it |
|---|---|
| `Test A` | `Test A Network`: a spare VLAN with no clients |
| `Test B` | `Test B Network`: a spare VLAN with no clients |

Each zone needs a network: the bouncer refuses a configured zone with none
("configured firewall zone … has no networks"), and the preflight stops there.

Then create an API key (Settings > Control Plane > Integrations), save it
alone in a file outside the repository, and create the gitignored
`e2e.local/udm.env`:

```
E2E_UDM_URL=https://<console address>
E2E_UDM_KEY_FILE=<path to the key file>
```

Run it:

```
E2E_UDM_CONFIRM=yes bash e2e.local/udm.sh
```

Optional overrides: `E2E_UDM_SITE` (default `default`) and `E2E_UDM_PAIR`
(default `Test A->Test B`). It uses the `crowdsec` service from this compose
file and the `cs-unifi-bouncer-pro:e2e` image, so rebuild that image first if
the code changed (`docker compose --profile bouncer build bouncer`). The key is
mounted read-only into the bouncer and piped to curl on stdin; it is never
printed or copied.

How it stays in scope:

- Another bouncer may already manage the same site (`crowdsec-policy-*`,
  `crowdsec-block-*`). Each run uses its own name prefix (`e2e-<id>-`),
  `OBJECT_DESCRIPTION` and data volume, so the two never touch each other's
  objects. The Cloudflare whitelist is off and the pair has no port or IP
  filters, which keeps the bouncer's fixed-name cleanup sweeps idle.
- The script edits or deletes an object only after re-reading it and seeing
  the run prefix.
- On any exit it drains, sweeps its leftovers, and diffs every other list,
  policy and zone against a before-snapshot. Any change is a failure, so do
  not edit the controller while it runs.

Sections (`E2E_UDM_SECTIONS`, default `main filters upgrade`), each ending
with a drain that must leave none of its objects:

- `main`: dry run with `FIREWALL_MODE=auto` (must resolve to zone and write
  nothing); provisioning; v4/v6 ban and unban; sharding at 5 per list; drift
  repair; SIGHUP and restart; drain.
- `filters`: the pair with destination ports and IPs plus the Cloudflare
  whitelist, checked on the controller, then restarted without either; the
  filter lists and Cloudflare objects must be removed.
- `upgrade`: the published `E2E_UDM_FROM` image (default `1.2.5`, a Docker Hub
  tag) bans IPv4, IPv6 and a `/32` range, then this checkout starts on the
  same database. It must migrate the `/32` ban once, keep every list and
  policy (same IDs, no duplicates), and release old bans on unban.

The `filters` section and releases up to 1.2.5 act on fixed names
(`crowdsec-ports-*`, `crowdsec-dstips-*`, `crowdsec-whitelist-cloudflare-*`)
site-wide, so the preflight refuses to run while any such object exists.

A full run takes about 20 minutes and writes logs and snapshots to
`e2e.local/udm-<run id>/` (gitignored: the snapshots hold the controller's
whole firewall configuration).

## What it covers

`run.sh` is split into numbered steps. Each step prints `PASS:`, `FAIL:` or `SKIP:` lines.

| Step | Checks |
|------|--------|
| 0  | Build, start, headless first-run wizard (`setup-unifi.sh`) |
| 1  | Standalone layout detected, auto mode resolved, JSON logs, `healthcheck` |
| 2-4 | v4 and v6 bans create groups and WAN_IN/WANv6_IN drop rules; unban removes |
| 5  | Private and whitelisted IPs never reach the controller |
| 5b | `x/32` and `x/128` range bans land as bare addresses (UniFi rejects host prefixes); a later ban still applies, no `FirewallGroupInvalidArgs`, circuit breaker closed |
| 6  | Sharding at capacity 40: 105 bulk IPs, one rule per shard, no duplicates or overflow |
| 7  | Blocklist feed applied; the feed token never appears in logs; a line with an inline `;` comment and a `/32` line are read |
| 7b | Feed answering 503 for 60s (3 refresh intervals) keeps its bans; a 200 with no valid entries keeps them too |
| 8  | Reconcile repairs shards emptied out of band and recreates a deleted rule; `reconcile_drift` webhook |
| 9  | Short decision expires and is removed |
| 10 | Restart: no duplicate groups or rules, IPs kept |
| 10b | Lost shard (v1.2.5 production bug): v4-1 deleted out of band and the bouncer's volume wiped while v4-2 exists; v4-2 keeps its ID (a wiped ban database must not strip enforced bans before the LAPI resends them), no duplicate names, one rule per shard, no needless rule rewrites, `shard_create_failures_total` and `unsynced_ips` stay 0 |
| 11 | Controller stopped and restarted: `/healthz` stays up, a ban queued during the outage lands afterwards |
| 12 | `status` refuses while the daemon holds bbolt; `validate` and `diagnose` pass |
| 13 | Metrics exported; LAPI key, UniFi password and panics absent from logs |
| 14 | API-key auth (needs `E2E_UNIFI_API_KEY`) |
| 15 | `DRY_RUN=true` makes no controller writes |
| 16 | SIGTERM exits 0; offline `status`/`ban`/`unban`; `drain --force` removes every `crowdsec-*` object |

## Files

| File | Purpose |
|------|---------|
| `run.sh` | The suite |
| `lib.sh` | Helpers shared by `run.sh` and `settings.sh` (`decide`, `has_ip`, `wait_for`, `metric`, `offline`, `case_up`/`case_down`, `rejects`, ...) |
| `settings.sh` | The settings matrix (see above) |
| `deploy.sh` | The deployment matrix (see above). Works in `.deploy/` |
| `udm.sh`, `udm-lib.sh` | Zone mode against a UniFi OS console (see above). Reads `udm.env` |
| `upgrade.sh` | `E2E_FROM=X.Y.Z`: the published release builds a ban database on the local stack, then this checkout takes it over. Needs a release that can log in to the self-hosted Network Application (after 1.2.5) |
| `up.sh` | Starts the stack and completes the wizard, leaving it up |
| `try.sh 'cmd'` | Runs a command with `lib.sh` loaded |
| `outage.sh` | Focused repro of step 11. Needs a stack left up with `KEEP=1`. Writes `outage-bouncer.log` and `outage-unifi.log` |
| `docker-compose.yml` | The stack. `E2E_FIREWALL_MODE`, `E2E_DRY_RUN` and `E2E_UNIFI_API_KEY` override bouncer env |
| `bouncer.env` | Bouncer settings: small shard capacity, short intervals, whitelist, feed URL with a token, webhook |
| `setup-unifi.sh` | Completes the first-run wizard and logs in, retrying until the controller persists the admin |
| `api.sh METHOD PATH [JSON]` | Calls the controller classic API with the admin session (`.cookies`), re-logging in on 401 |
| `probe.sh PATH...` | GET several paths and print status and body head. Set `APIKEY=` to send `X-API-KEY` |
| `q.js 'expr'` | Evaluates a JS expression on JSON from stdin (`d` = document, `data` = `d.data`) |
| `wait-unifi.sh` | Blocks until `/status` answers |
| `init-mongo.sh` | Creates the MongoDB user the controller expects |
| `mock/` | Go server: `/blocklist.txt` (`PUT /_blocklist` replaces it, `PUT /_feedstatus` with `503` makes it fail and `0` restores it), `POST /webhook`, `POST /webhook/fail` (500), `POST /webhook/slow` (answers after a minute), `GET /_hookattempts`, `GET /_webhooks` (received payloads), `GET /_fetches` (feed fetch count) |

These artifacts are written on each run and can be deleted: `bouncer.log`
(bouncer logs accumulated across restarts), `webhooks.json`, `.cookies`,
`cases/`, `secrets/`, `.deploy/`, `udm-*/` and the `outage-*.log` files. All
are gitignored.

## Useful commands with the stack up (`KEEP=1`)

```bash
cd e2e.local
bash api.sh GET /api/s/default/rest/firewallgroup | node q.js "data.map(g => [g.name, g.group_members.length])"
bash api.sh GET /api/s/default/rest/firewallrule  | node q.js "data.filter(r => r.name.startsWith('crowdsec-')).map(r => r.name)"
docker compose --profile bouncer exec -T crowdsec cscli decisions add -i 203.0.113.50 -d 1h
docker compose --profile bouncer logs -f bouncer
curl -s http://127.0.0.1:19090/metrics | grep crowdsec_unifi_
docker compose --profile bouncer run --rm -T bouncer diagnose   # stop the daemon first for status/ban/unban
```

## Controller behaviour worth knowing

- This is a standalone Network Application. It has no `/proxy/network` prefix,
  logs in via `/api/login`, and `GET /` returns 302. UniFi OS consoles differ.
- While starting or stopping it answers 404 on every API path, and `GET /`
  returns 404. The bouncer treats that as "not ready", not as "object deleted".
- A duplicate name returns HTTP 400 with `api.err.FirewallGroupExisted` (or
  similar `...Existed`), not 409.
- The integration v1 API (zone mode, traffic-matching lists) needs an API key.
  A session gets 403, and this controller cannot issue keys or hold zones (no
  gateway), which is why the e2e runs exercise legacy mode only.
- `192.0.2.1` is also the bouncer's creation placeholder, and the step 6 bulk set
  deliberately bans it.

## Adding a check

1. Pick the step it belongs to, or add a new numbered `step`.
2. Use `check "<description>" <command>` for an instant assertion. Use
   `wait_for <seconds> "<description>" <command>` for anything the bouncer
   applies asynchronously.
3. If you recreate the bouncer, use `restart_bouncer` so its logs are saved to
   `bouncer.log` first.
4. Run the CLI subcommands that open bbolt (`status`, `ban`, `unban`, `drain`)
   through `offline` with the daemon stopped.
5. Never hard-code real credentials. Everything here is throwaway and bound to 127.0.0.1.
