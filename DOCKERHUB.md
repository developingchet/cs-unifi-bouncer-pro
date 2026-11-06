![CrowdSec Unifi Bouncer Logo](https://raw.githubusercontent.com/developingchet/cs-unifi-bouncer-pro/main/docs/logo.png)

# cs-unifi-bouncer-pro

[![Build](https://github.com/developingchet/cs-unifi-bouncer-pro/actions/workflows/release.yml/badge.svg)](https://github.com/developingchet/cs-unifi-bouncer-pro/actions/workflows/release.yml) [![Version](https://img.shields.io/badge/version-v2.3.0-blue)](https://github.com/developingchet/cs-unifi-bouncer-pro/releases/tag/v2.3.0) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/LICENSE) [![Docker Pulls](https://img.shields.io/docker/pulls/developingchet/cs-unifi-bouncer-pro)](https://hub.docker.com/r/developingchet/cs-unifi-bouncer-pro)

---

## Summary

cs-unifi-bouncer-pro is a [CrowdSec](https://crowdsec.net) bouncer for [UniFi](https://ui.com) network controllers: UniFi OS consoles, UniFi OS Server and the self-hosted Network Application. It turns CrowdSec ban decisions into UniFi firewall objects, so malicious addresses are blocked at the gateway.

It uses zone-based policies or legacy `WAN_IN` rules, chosen per site at startup, applies bans across multiple sites, and packs addresses into sharded groups or traffic matching lists that are created and merged as the ban list changes. Bans are persisted in a bbolt database, a configurable circuit breaker handles controller outages, and startup and periodic reconciles correct drift. The image is distroless, about an 8 MB download (about 31 MB unpacked), runs as nonroot (UID 65532), and is Cosign-signed with a CycloneDX SBOM attached to every release.

> **Upgrading from 1.x?** 2.0 changes several defaults and rejects settings 1.x accepted. Read the [upgrade guide](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/docs/UPGRADING.md) before you pull the new image.

---

## Quick Start

```yaml
services:
  bouncer:
    image: developingchet/cs-unifi-bouncer-pro:latest
    restart: unless-stopped
    environment:
      UNIFI_URL: https://192.168.1.1
      UNIFI_API_KEY: your-api-key
      CROWDSEC_LAPI_URL: http://crowdsec:8080
      CROWDSEC_LAPI_ALLOW_HTTP: "true"
      CROWDSEC_LAPI_KEY: your-bouncer-key
      ZONE_PAIRS: External->Dmz
    volumes:
      - bouncer-data:/data
volumes:
  bouncer-data:
```

For full setup including CrowdSec registration, TLS, multi-site, and Docker Secrets support, see the [Setup Guide](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/docs/SETUP.md).

---

## Features

- **Both firewall generations** — zone-based policies or legacy `WAN_IN` rules, chosen per site at startup. UniFi Network 11 is zone-based only: legacy sites switch to zone mode after the controller upgrade
- **Multi-site** — bans applied to all configured UniFi sites from a single instance
- **Batch sync with bin-packing** — fills shards before creating new ones; changed shards are written after each decision batch
- **Shard rebalance** — merges under-filled shards after bans expire (`SHARD_MERGE_THRESHOLD`)
- **Circuit breaker** — configurable failure threshold and cooldown; suspends syncs when the controller is unhealthy
- **Crash-safe bbolt persistence** — bans are recorded before the controller write; startup and periodic reconciles correct drift
- **28 Prometheus metrics** — decisions, API calls, active bans, unsynced bans, shard occupancy, decision latency, circuit breaker state
- **Decision latency histogram** — time from receiving a ban to recording it in the ban database and its shard
- **CrowdSec usage-metrics** — decision telemetry pushed to LAPI `/v1/usage-metrics` (default: 30 min; configurable)
- **Egress blocking** — optional `EGRESS_ZONE_PAIRS` stops hosts in zones such as a DMZ or IoT network from connecting out to banned addresses, using the same ban lists
- **Cloudflare whitelist sync** — ALLOW policies for Cloudflare IP ranges, auto-refreshed on a configurable schedule; block policies created before the allow are recreated behind it so it takes effect
- **Ban history audit trail** — ring-buffer event log (up to 10,000 entries) for every ban, unban, and expiry; queryable via `status bans`, `status ip`, `status history`, also against the running bouncer via `docker exec`
- **External blocklist import** — fetch plain-text IP/CIDR lists from external URLs on a configurable interval; bans auto-expire if the feed goes offline
- **AbuseIPDB lists with country filters** — import a borestad AbuseIPDB list by report window and include or exclude two-letter country codes; configure `ABUSEIPDB_LIST` and optionally `ABUSEIPDB_COUNTRY_INCLUDE`, `ABUSEIPDB_COUNTRY_EXCLUDE`, and `ABUSEIPDB_REFRESH_INTERVAL`
- **Webhook notifications** — POST JSON alerts when the circuit breaker trips or reconcile drift is detected
- **Per-scenario duration overrides** — set a duration for matching CrowdSec scenarios via `BLOCK_SCENARIO_DURATION_MAP`, including durations longer than `BAN_TTL`
- **Destination IP filtering** — scope block policies to specific destination hosts or subnets via `@ip1,ip2,...` suffix on zone pairs
- **Decision rate limiter** — token-bucket throttle for ban waves (`DECISION_RATE_LIMIT`)
- **Validate and diagnose subcommands** — CI-safe config validation; LAPI, controller, UniFi Network version and firewall-mode checks with zone discovery (`--lapi-auth` also checks the LAPI key)
- **Log redaction** — passwords, API keys and Bearer tokens are masked before log lines are written
- **Dry-run mode** — connects and reads live state; logs all intended changes without writing anything to UniFi
- **Multi-arch distroless image** — amd64, arm64, armv7; about an 8 MB download; runs as nonroot (UID 65532)
- **Cosign-signed + CycloneDX SBOM** — keyless OIDC image signing and SBOM attestation on every release

---

## Required Configuration

| Variable | Example | Description |
|----------|---------|-------------|
| `UNIFI_URL` | `https://192.168.1.1` | UniFi controller base URL |
| `UNIFI_API_KEY` | `your-api-key` | API key (Settings → Control Plane → Integrations); or use `UNIFI_USERNAME` + `UNIFI_PASSWORD`, which manage legacy firewall rules only |
| `CROWDSEC_LAPI_KEY` | `your-bouncer-key` | Bouncer key from `cscli bouncers add unifi-bouncer` |

Commonly set as well:

| Variable | Default | Description |
|----------|---------|-------------|
| `CROWDSEC_LAPI_URL` | `https://crowdsec:8080` | CrowdSec LAPI URL; an `http://` URL also needs `CROWDSEC_LAPI_ALLOW_HTTP=true`, for a trusted local network only |
| `ZONE_PAIRS` | `External->Dmz` | Zone pairs whose inbound traffic is blocked on zone-based sites; `src[:sport,...]->dst[:dport,...][@dstIP,...]` — port and destination IP filters are optional |
| `UNIFI_SITES` | `default` | Comma-separated sites to manage |

Sensitive variables (`UNIFI_API_KEY`, `UNIFI_USERNAME`, `UNIFI_PASSWORD`, `CROWDSEC_LAPI_KEY`) accept a `_FILE` suffix for Docker secrets and Kubernetes secret mounts. For the full variable reference see the [Configuration Reference](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/docs/CONFIGURATION.md).

---

## Image Tags

| Tag | When to use |
|-----|-------------|
| `latest` | stable, always points to the newest release |
| `2.3.0` (also `v2.3.0`) | exact version, recommended for production |
| `2.3` | minor-pinned |
| `2` | major-pinned |

---

## Supply Chain

This image is signed with [Cosign](https://docs.sigstore.dev/cosign/overview/) (keyless OIDC). Verify with:

```bash
cosign verify developingchet/cs-unifi-bouncer-pro:2.3.0 \
  --certificate-identity-regexp="https://github.com/developingchet/cs-unifi-bouncer-pro/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

A CycloneDX SBOM is attached to each release and embedded as a Cosign attestation on the image.

---

## Links

- [GitHub Repository](https://github.com/developingchet/cs-unifi-bouncer-pro)
- [Full README](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/README.md)
- [Configuration Reference](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/docs/CONFIGURATION.md)
- [Setup Guide](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/docs/SETUP.md)
- [Upgrade Guide](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/docs/UPGRADING.md)
- [Troubleshooting](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/docs/TROUBLESHOOTING.md)
- [Security Policy](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/SECURITY.md)
- [Docker Hub Image](https://hub.docker.com/r/developingchet/cs-unifi-bouncer-pro)
