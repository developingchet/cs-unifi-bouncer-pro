# Security & Supply Chain Compliance

This document describes the security posture and supply chain controls for
cs-unifi-bouncer-pro. It is written for security reviewers and contributors
who need to verify the integrity of published artifacts or assess the runtime
hardening of deployed containers. It describes the current
`.github/workflows/release.yml` and container configuration.

---

## Supply Chain Security

Every release tag (`v*.*.*`) triggers `.github/workflows/release.yml`. The
controls below are applied to every published artifact.

### Release Source Checks

Job `verify` fails the release unless the tagged commit is reachable from
`origin/main` (`git merge-base --is-ancestor`). Release jobs do not restore
the Go or Docker build caches, so a cache entry written by an earlier workflow
run cannot reach a released artifact.

### Trivy Vulnerability Scan

Job `docker-scan`, step **"Trivy vulnerability scan"**
(`aquasecurity/trivy-action` v0.36.0, pinned by commit SHA):

- Scans the `linux/amd64` candidate image before anything is pushed.
- `exit-code: "1"` — the workflow fails and no image is published if unfixed
  vulnerabilities at `HIGH` or `CRITICAL` severity are found.
- `ignore-unfixed: true` — vulnerabilities with no available fix do not block
  the release.

Job `docker-push` then scans the pushed multi-arch image by digest, once per
platform (`linux/amd64`, `linux/arm64`, `linux/arm/v7`), with the same
settings. The scans run before signing and before the version tags are
published.

### Cosign Keyless Image Signing

Job `docker-push`, step **"Sign image with Cosign (keyless OIDC)"**:

The multi-arch image is signed with Cosign using GitHub Actions OIDC — no
long-lived signing key exists. The signature is bound to the exact release
workflow identity.

```bash
cosign verify developingchet/cs-unifi-bouncer-pro:2.3.0 \
  --certificate-identity-regexp="https://github.com/developingchet/cs-unifi-bouncer-pro/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

### Build Provenance

Job `docker-push`, step **"Attest image build provenance"**, and job
`release`, step **"Attest binary build provenance"**
(`actions/attest-build-provenance` v4.2.2, pinned by commit SHA), record SLSA
provenance for the image digest and for the release binaries, signed through
GitHub Actions OIDC. The image attestation is also pushed to the registry.

```bash
gh attestation verify oci://developingchet/cs-unifi-bouncer-pro:2.3.0 \
  --repo developingchet/cs-unifi-bouncer-pro
gh attestation verify cs-unifi-bouncer-pro-linux-amd64 \
  --repo developingchet/cs-unifi-bouncer-pro
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
(`docker/build-push-action` v7.4.0, pinned by commit SHA),
`platforms: linux/amd64,linux/arm64,linux/arm/v7`.

---

## Runtime Security Controls

### Seccomp Profile

- Profile path: `security/seccomp-unifi.json`
- Default action: `SCMP_ACT_ERRNO` — all syscalls are denied unless explicitly
  listed.
- Allowlist: the syscalls required by the Go runtime, bbolt, and TLS network I/O.
- Namespaces: `clone` is allowed only when none of the namespace flags
  (`CLONE_NEWNS`, `CLONE_NEWCGROUP`, `CLONE_NEWUTS`, `CLONE_NEWIPC`,
  `CLONE_NEWUSER`, `CLONE_NEWPID`, `CLONE_NEWNET`) are set. `clone3` returns
  `ENOSYS`, which makes the Go runtime fall back to `clone`; its flags are
  passed in a struct that seccomp cannot inspect.

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

Actions in the CI, release, image-scan, Scorecard, and Socket workflows are
pinned to full commit SHAs. The YAML comments identify these upstream versions;
the SHA references in the workflow files are the source of truth.

| Action | Upstream version | Workflows |
|--------|------------------|-----------|
| `actions/attest-build-provenance` | v4.2.2 | release |
| `actions/checkout` | v7.0.1 | CI, release, Socket, Scorecard |
| `actions/download-artifact` | v8 | release |
| `actions/setup-go` | v7 | CI, release |
| `actions/setup-python` | v7.0.0 | Socket |
| `actions/upload-artifact` | v7.0.1 | release, Scorecard |
| `anchore/sbom-action` | v0 | release |
| `aquasecurity/trivy-action` | v0.36.0 | CI, release, image-scan |
| `github/codeql-action/upload-sarif` | v4.38.2 | release, image-scan, Scorecard |
| `docker/build-push-action` | v7.4.0 | CI, release |
| `docker/login-action` | v4.6.0 | release |
| `docker/metadata-action` | v6.2.0 | release |
| `docker/setup-buildx-action` | v4.4.1 | CI, release |
| `docker/setup-qemu-action` | v4.4.0 | release |
| `golangci/golangci-lint-action` | v9 | CI |
| `ossf/scorecard-action` | v2.4.4 | Scorecard |
| `peter-evans/dockerhub-description` | v5.0.0 | release |
| `sigstore/cosign-installer` | v4.1.2 | release |
| `softprops/action-gh-release` | v2 | release |

CI runs race tests, lint, `govulncheck`, and a container scan before a release.
The weekly image-scan workflow checks published images for newly disclosed
fixable vulnerabilities. Scorecard uploads repository security findings, and
Socket scans Go modules and GitHub Actions on pull requests and `main` when
its API key is configured.

---

## Verification Commands

Independent verification of each supply chain claim:

```bash
# Verify image signature
cosign verify developingchet/cs-unifi-bouncer-pro:2.3.0 \
  --certificate-identity-regexp="https://github.com/developingchet/cs-unifi-bouncer-pro/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

# Inspect SBOM attestation
cosign verify-attestation developingchet/cs-unifi-bouncer-pro:2.3.0 \
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
