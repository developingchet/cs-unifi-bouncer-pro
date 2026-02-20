# Security Policy

## Supported Versions

Only the latest release receives security fixes. Older versions are unsupported.

| Version | Supported |
|---------|-----------|
| latest  | ✓         |
| < latest | ✗        |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately via [GitHub Security Advisories](https://github.com/developingchet/cs-unifi-bouncer-pro/security/advisories/new).

### Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | 3 business days |
| Status update | 7 business days |
| Remediation target | 30 days from confirmed reproduction |
| Critical (CVSS ≥ 9.0) | Expedited — best effort |

We follow coordinated vulnerability disclosure. We will credit reporters in the release notes unless anonymity is requested.

## Security Features

### Runtime Isolation

The Docker image is hardened by default:

- **Distroless base** (`gcr.io/distroless/static-debian12`) — no shell, no package manager, no OS utilities
- **Non-root user** — runs as UID 65532 (`nonroot`)
- **Dropped capabilities** — `cap_drop: ALL` in `docker-compose.yml`
- **Read-only filesystem** — `read_only: true` in `docker-compose.yml`; only `/tmp` and the data volume are writable
- **Seccomp profile** — `security/seccomp-unifi.json` restricts the bouncer to the exact syscalls required; all others return `EPERM`
- **No new privileges** — `no-new-privileges:true` prevents privilege escalation via setuid binaries

### Secret Protection

- All credentials (passwords, API keys, LAPI key) are loaded exclusively from environment variables or `_FILE` variants (Docker/Kubernetes secrets)
- A `RedactWriter` wraps every log output path and replaces sensitive values with `[REDACTED]` before they are written — API keys, passwords, and Bearer tokens never appear in logs even if accidentally referenced
- Credentials are never written to disk

### Network Security

- All outbound connections to the UniFi controller and CrowdSec LAPI enforce TLS 1.2 minimum
- Self-signed certificate support via `UNIFI_CA_CERT` (avoid disabling verification in production)
- HTTP timeouts configured via `UNIFI_HTTP_TIMEOUT` (default 15 s) and `SESSION_REAUTH_TIMEOUT`

### Supply Chain Integrity

Every release tag triggers a GitHub Actions workflow that:

1. Builds multi-arch Docker images (`amd64`, `arm64`, `arm/v7`)
2. Runs **Trivy** vulnerability scanning — blocks on `HIGH`/`CRITICAL` unfixed CVEs
3. Signs the image with **Cosign** keyless OIDC (no long-lived signing key)
4. Generates a **CycloneDX SBOM** and attaches it as an OCI attestation
5. Publishes binaries via **GoReleaser** with checksums

To verify a release image:

```bash
# Verify Cosign signature
cosign verify ghcr.io/developingchet/cs-unifi-bouncer-pro:latest \
  --certificate-identity-regexp="https://github.com/developingchet/cs-unifi-bouncer-pro" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

# Download and verify SBOM
cosign download attestation ghcr.io/developingchet/cs-unifi-bouncer-pro:latest \
  | jq -r '.payload | @base64d | fromjson | .predicate'
```

## Vulnerability Scope

### In Scope

- The Go bouncer binary (`cmd/bouncer/`)
- `Dockerfile` and container configuration
- GitHub Actions workflows (`.github/workflows/`)
- Published Docker images on GHCR

### Out of Scope

- CrowdSec LAPI (upstream — report to CrowdSec)
- UniFi controller firmware or API (report to Ubiquiti)
- Denial-of-service attacks requiring access to the metrics/health port (`:9090`, `:8081`)
- Theoretical exploits without a demonstrated attack path

## Dependency Updates

Dependabot is configured to keep Go modules and GitHub Actions up to date. CVE patches in indirect dependencies are addressed on a best-effort basis as they appear in Trivy scans.
