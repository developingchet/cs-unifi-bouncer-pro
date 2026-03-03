<p align="center">
  <img src="https://github.com/user-attachments/assets/cd0d1ec5-8e15-48f4-b4fb-f28dec6629c2" width="590" alt="CrowdSec Unifi Bouncer Logo">
</p>

# cs-unifi-bouncer-pro

[![Build](https://github.com/developingchet/cs-unifi-bouncer-pro/actions/workflows/release.yml/badge.svg)](https://github.com/developingchet/cs-unifi-bouncer-pro/actions/workflows/release.yml) [![Version](https://img.shields.io/badge/version-v1.1.4-blue)](https://github.com/developingchet/cs-unifi-bouncer-pro/releases/tag/v1.1.4) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/LICENSE) [![Docker Pulls](https://img.shields.io/docker/pulls/developingchet/cs-unifi-bouncer-pro)](https://hub.docker.com/r/developingchet/cs-unifi-bouncer-pro)

---

## Summary

cs-unifi-bouncer-pro is a production-grade [CrowdSec](https://crowdsec.net) bouncer for self-hosted [UniFi](https://ui.com) network controllers that automatically translates ban decisions into firewall rules, blocking malicious IPs at the network edge in real time. It auto-detects zone-based (UniFi Network ≥ 8.x) or legacy WAN_IN firewall modes, applies bans across multiple sites simultaneously, and manages multi-shard Traffic Matching Lists with bin-packing and automatic rebalance. Bans are persisted in a crash-safe bbolt database with bbolt-first write ordering, and a configurable three-state circuit breaker handles controller outages gracefully. Cloudflare IP whitelist sync, 20 Prometheus metrics with decision latency histograms, and `validate`/`diagnose` subcommands complete the production hardening. The image is distroless, under 20 MB, runs as nonroot (UID 65532), and is Cosign-signed with a CycloneDX SBOM attached to every release.

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
      CROWDSEC_LAPI_KEY: your-bouncer-key
      ZONE_PAIRS: External->Internal
    volumes:
      - bouncer-data:/data
volumes:
  bouncer-data:
```

For full setup including CrowdSec registration, TLS, multi-site, and Docker Secrets support, see the [Setup Guide](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/docs/SETUP.md).

---

## Features

- **Dual firewall modes** — auto-detects zone-based (UniFi ≥ 8.x) or legacy WAN_IN; no manual config required
- **Multi-site** — bans applied to all configured UniFi sites simultaneously from a single instance
- **Batch sync with bin-packing** — fills shards before creating new ones; dirty shards flushed immediately after each decision batch
- **Shard rebalance** — collapses under-filled TMLs automatically after expiry (`SHARD_MERGE_THRESHOLD`)
- **Circuit breaker** — configurable failure threshold and cooldown; suspends syncs when the controller is unhealthy
- **Crash-safe bbolt persistence** — bbolt-first write ordering; startup reconcile corrects drift after a crash or restart
- **20 Prometheus metrics** — decisions, API calls, active bans, shard occupancy, decision latency, circuit breaker state
- **Decision latency histogram** — end-to-end timing from CrowdSec filter pipeline to successful UniFi write
- **CrowdSec usage-metrics** — decision telemetry pushed to LAPI `/v1/usage-metrics` (default: 30 min; configurable)
- **Cloudflare whitelist sync** — ALLOW policies for Cloudflare IP ranges, auto-refreshed on a configurable schedule
- **Validate and diagnose subcommands** — CI-safe config validation; three-phase connectivity check with zone discovery
- **Log redaction** — RedactWriter masks passwords, API keys, and Bearer tokens before they reach stdout
- **Dry-run mode** — connects and reads live state; logs all intended changes without writing anything to UniFi
- **Multi-arch distroless image** — amd64, arm64, armv7; under 20 MB; runs as nonroot (UID 65532)
- **Cosign-signed + CycloneDX SBOM** — keyless OIDC image signing and SBOM attestation on every release

---

## Required Configuration

| Variable | Example | Description |
|----------|---------|-------------|
| `UNIFI_URL` | `https://192.168.1.1` | UniFi controller base URL |
| `UNIFI_API_KEY` | `your-api-key` | API key (Settings → Control Plane → API Keys); or use `UNIFI_USERNAME` + `UNIFI_PASSWORD` |
| `CROWDSEC_LAPI_URL` | `http://crowdsec:8080` | CrowdSec LAPI URL (default assumes a Docker service named `crowdsec`) |
| `CROWDSEC_LAPI_KEY` | `your-bouncer-key` | Bouncer key from `cscli bouncers add unifi-bouncer` |
| `ZONE_PAIRS` | `External->Internal` | Zone pair(s) for block policies; comma-separated `src[:sport,...]->dst[:dport,...]` (port lists are optional) |

Sensitive variables (`UNIFI_API_KEY`, `UNIFI_PASSWORD`, `CROWDSEC_LAPI_KEY`) accept a `_FILE` suffix for Docker secrets and Kubernetes secret mounts. For the full variable reference see the [Configuration Reference](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/docs/CONFIGURATION.md).

---

## Image Tags

| Tag | When to use |
|-----|-------------|
| `latest` | stable, always points to the newest release |
| `v1.1.4` | exact version, recommended for production |
| `1.0` | minor-pinned |
| `1` | major-pinned |

---

## Supply Chain

This image is signed with [Cosign](https://docs.sigstore.dev/cosign/overview/) (keyless OIDC). Verify with:

```bash
cosign verify developingchet/cs-unifi-bouncer-pro:v1.1.4 \
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
- [Troubleshooting](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/docs/TROUBLESHOOTING.md)
- [Security Policy](https://github.com/developingchet/cs-unifi-bouncer-pro/blob/main/SECURITY.md)
- [Docker Hub Image](https://hub.docker.com/r/developingchet/cs-unifi-bouncer-pro)
