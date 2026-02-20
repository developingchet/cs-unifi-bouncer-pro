# cs-unifi-bouncer-pro

A production-grade [CrowdSec](https://crowdsec.net) bouncer for [UniFi](https://ui.com) network controllers.

Automatically translates CrowdSec ban decisions into UniFi firewall rules — blocking malicious IPs at the network edge across all configured sites, in real time.

---

## Quick Start

```bash
# 1. Register the bouncer with CrowdSec
docker exec crowdsec cscli bouncers add unifi-bouncer

# 2. Clone and configure
git clone https://github.com/developingchet/cs-unifi-bouncer-pro.git
cd cs-unifi-bouncer-pro
cp .env.example .env
# Edit .env: set UNIFI_URL, UNIFI_API_KEY, CROWDSEC_LAPI_KEY

# 3. Launch
docker compose up -d

# 4. Verify
docker logs -f cs-unifi-bouncer-pro
```

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Dual firewall modes** | Auto-detects zone-based (UniFi ≥ 8.x) or legacy WAN_IN rules |
| **Multi-site** | Bans applied to all configured UniFi sites simultaneously |
| **Worker pool** | 1–64 goroutines with exponential backoff retry |
| **ACID persistence** | bbolt-backed ban tracking; survives container restarts |
| **Template naming** | Go templates prevent naming conflicts in multi-instance deployments |
| **Prometheus metrics** | 15 `crowdsec_unifi_*` metrics for full observability |
| **Log redaction** | Passwords, API keys, and Bearer tokens never appear in logs |
| **Dry-run mode** | Log all actions without modifying the UniFi controller |
| **Startup reconcile** | Syncs UniFi firewall state with bbolt on every start |

---

## Required Environment Variables

| Variable | Description |
|----------|-------------|
| `UNIFI_URL` | UniFi controller URL (e.g. `https://192.168.1.1`) |
| `UNIFI_API_KEY` | UniFi API key **or** `UNIFI_USERNAME` + `UNIFI_PASSWORD` |
| `CROWDSEC_LAPI_KEY` | Bouncer key from `cscli bouncers add` |

---

## Firewall Modes

### auto (recommended)
Detects zone-based firewall support from the UniFi controller version. Uses zone policies on UniFi Network ≥ 8.x, legacy WAN_IN rules on older firmware.

### legacy
Creates `WAN_IN` / `WANv6_IN` drop rules referencing managed address-group shards. Compatible with all UniFi Network versions.

### zone
Creates zone firewall policies for each configured `ZONE_PAIRS` (e.g. `External->Internal,External->IoT`). Requires UniFi Network ≥ 8.x.

---

## Security Properties

- Runs as UID 65532 (`nonroot`) in a distroless container
- No shell, no package manager, no OS utilities in the image
- `cap_drop: ALL` — all Linux capabilities dropped
- Read-only root filesystem; only `/tmp` and the data volume are writable
- Seccomp syscall allowlist (`security/seccomp-unifi.json`)
- All credentials loaded from environment variables only — never written to disk
- Docker images signed with Cosign (keyless OIDC) and accompanied by a CycloneDX SBOM

---

## Observability

**Prometheus metrics** at `:9090/metrics`

| Metric | Description |
|--------|-------------|
| `crowdsec_unifi_active_bans` | Currently banned IPs per site and address family |
| `crowdsec_unifi_decisions_processed_total` | Total decisions received from CrowdSec |
| `crowdsec_unifi_decisions_filtered_total` | Decisions dropped at each filter stage |
| `crowdsec_unifi_jobs_processed_total` | Worker pool throughput |
| `crowdsec_unifi_api_duration_seconds` | UniFi API call latency histogram |
| `crowdsec_unifi_reconcile_duration_seconds` | Full reconcile duration |

**Health endpoints** at `:8081`

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Liveness — always returns 200 if the process is running |
| `GET /readyz` | Readiness — returns 200 only if the UniFi controller is reachable |

---

## CLI Commands

```bash
cs-unifi-bouncer-pro run          # Start the daemon
cs-unifi-bouncer-pro healthcheck  # Exit 0 if healthy (used by Docker healthcheck)
cs-unifi-bouncer-pro reconcile    # One-shot full reconcile then exit
cs-unifi-bouncer-pro version      # Print version and build info
```

---

## Full Documentation

- [Setup Guide](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/docs/SETUP.md)
- [Configuration Reference](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/docs/CONFIGURATION.md)
- [Architecture & Design](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/docs/DESIGN.md)
- [Troubleshooting](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/docs/TROUBLESHOOTING.md)

---

## License

MIT — see [LICENSE](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/LICENSE)
