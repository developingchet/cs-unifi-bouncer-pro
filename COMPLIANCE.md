# Security & Supply Chain Compliance

This document describes the security posture and supply chain controls for
cs-unifi-bouncer-pro. It is written for auditors, operators, and contributors
who need to verify the integrity of published artifacts or assess the runtime
hardening of deployed containers. It covers release **v1.0.0** and all
subsequent releases produced by `.github/workflows/release.yml`.

---

## Supply Chain Security

Every release tag (`v*.*.*`) triggers `.github/workflows/release.yml`. The
controls below are applied to every published artifact.

### Trivy Vulnerability Scan

Job `docker-scan`, step **"Trivy vulnerability scan"**
(`aquasecurity/trivy-action@0.28.0`):

- Scans the `linux/amd64` candidate image before anything is pushed.
- `exit-code: "1"` — the workflow fails and no image is published if unfixed
  vulnerabilities at `HIGH` or `CRITICAL` severity are found.
- `ignore-unfixed: true` — vulnerabilities with no available fix do not block
  the release.

### Cosign Keyless Image Signing

Job `docker-push`, step **"Sign image with Cosign (keyless OIDC)"**:

The multi-arch image is signed with Cosign using GitHub Actions OIDC — no
long-lived signing key exists. The signature is bound to the exact release
workflow identity.

```bash
cosign verify developingchet/cs-unifi-bouncer-pro:v1.0.0 \
  --certificate-identity-regexp="https://github.com/developingchet/cs-unifi-bouncer-pro/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

### CycloneDX SBOM

Job `docker-push`, steps **"Generate SBOM (CycloneDX)"**
(`anchore/sbom-action@v0`, format `cyclonedx-json`) and **"Attach SBOM
attestation"** (`cosign attest --type cyclonedx`):

- The SBOM is attached as a Cosign OCI attestation on the published image
  digest.
- The SBOM is also uploaded as a release artifact:
  `cs-unifi-bouncer-pro.sbom.cyclonedx.json`.

### Binary Checksums

Job `release`, step **"Generate checksums"**:

```bash
sha256sum * > checksums.txt
```

`checksums.txt` is published alongside every release and covers all artifacts:

- `cs-unifi-bouncer-pro-linux-amd64`
- `cs-unifi-bouncer-pro-linux-arm64`
- `cs-unifi-bouncer-pro-linux-armv7`
- `cs-unifi-bouncer-pro.sbom.cyclonedx.json`

### Multi-Architecture Image

Job `docker-push`, step **"Build and push multi-arch image"**
(`docker/build-push-action@v5`), `platforms: linux/amd64,linux/arm64,linux/arm/v7`.

---

## Runtime Security Controls

### Seccomp Profile

- Profile path: `security/seccomp-unifi.json`
- Default action: `SCMP_ACT_ERRNO` — all syscalls are denied unless explicitly
  listed.
- Allowlist: 91 syscalls required by the Go runtime, bbolt, and TLS network I/O.

CI validation runs on every push and pull request in two stages
(`.github/workflows/ci.yml`):

1. Job **"Validate Seccomp Profile"** (`validate-seccomp`) — static JSON
   validation via `scripts/validate-seccomp.sh`.

2. Job **"Seccomp Integration Test"** (`test-seccomp`) — builds the production
   image and runs it under the profile with `--cap-drop ALL` and
   `no-new-privileges:true`. Exit code 159 (SIGSYS) means a required syscall
   was blocked by the profile; the job asserts the exit code is not 159.

### Container Capabilities

`cap_drop: ALL` — all Linux capabilities are dropped at container start.
Source: `docker-compose.standalone.yml`.

### Filesystem

`read_only: true` — the root filesystem is mounted read-only.
Source: `docker-compose.standalone.yml`.

Writable paths:
- `/tmp` — tmpfs, `size=10m,noexec,nosuid`
- `/data` — named Docker volume (bbolt database)

### Non-Root User

The runtime image is built on `gcr.io/distroless/static-debian12:nonroot`
(Dockerfile, stage 2). The data directory is owned by UID **65532**
(`--chown=65532:65532`, Dockerfile). The process runs as UID **65532** at
runtime.

### No New Privileges

`no-new-privileges:true` — prevents privilege escalation via setuid/setgid
binaries. Source: `docker-compose.standalone.yml`.

---

## Dependency Management

Go module dependencies are pinned by exact version in `go.mod` and locked by
cryptographic hash in `go.sum`. To audit the full dependency tree:

```bash
go list -m -json all | jq '{module: .Path, version: .Version}'
govulncheck ./...
```

Dependabot is configured to keep Go modules and GitHub Actions up to date.
CVE patches in indirect dependencies are addressed as they appear in Trivy scans.

---

## Vulnerability Reporting

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy,
private reporting channel, and response timelines.

---

## Workflow Integrity

All actions in `.github/workflows/ci.yml` and `.github/workflows/release.yml`
use pinned versions. The table below is copied verbatim from the workflow files.

| Action | Version tag used | Workflow |
|--------|-----------------|---------|
| `actions/checkout` | `@v4` | ci.yml, release.yml |
| `actions/download-artifact` | `@v4` | release.yml |
| `actions/setup-go` | `@v5` | ci.yml, release.yml |
| `actions/upload-artifact` | `@v4` | release.yml |
| `anchore/sbom-action` | `@v0` | release.yml |
| `aquasecurity/trivy-action` | `@0.28.0` | release.yml |
| `docker/build-push-action` | `@v5` | ci.yml, release.yml |
| `docker/login-action` | `@v3` | release.yml |
| `docker/metadata-action` | `@v5` | release.yml |
| `docker/setup-buildx-action` | `@v3` | ci.yml, release.yml |
| `docker/setup-qemu-action` | `@v3` | release.yml |
| `peter-evans/dockerhub-description` | `@v4` | release.yml |
| `sigstore/cosign-installer` | `@v3` | release.yml |
| `softprops/action-gh-release` | `@v2` | release.yml |

> **Note:** Actions are currently pinned to version tags, not commit SHAs.
> See [GitHub Actions security hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)
> for SHA-pinning guidance. SHA pinning is tracked as a planned hardening item.

---

## Verification Commands

Independent verification of each supply chain claim:

```bash
# Verify image signature
cosign verify developingchet/cs-unifi-bouncer-pro:v1.0.0 \
  --certificate-identity-regexp="https://github.com/developingchet/cs-unifi-bouncer-pro/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

# Inspect SBOM attestation
cosign verify-attestation developingchet/cs-unifi-bouncer-pro:v1.0.0 \
  --type cyclonedx \
  --certificate-identity-regexp="https://github.com/developingchet/cs-unifi-bouncer-pro/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  | jq .payload | base64 -d | jq .subject

# Verify binary checksums
sha256sum --check checksums.txt

# Count allowed syscalls in the seccomp profile
jq '.syscalls[0].names | length' security/seccomp-unifi.json

# Audit Go dependency versions
go list -m -json all | jq '{module: .Path, version: .Version}'
govulncheck ./...
```
