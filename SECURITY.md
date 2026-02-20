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

### Seccomp profile

The profile (`security/seccomp-unifi.json`) uses `SCMP_ACT_ERRNO` as the default
action — all syscalls are denied unless explicitly listed.

The allowlist is grouped into three categories:

#### Go runtime initialization (required at startup, not called by application logic)

| Syscall | Reason |
|---|---|
| `execve` | runc requires this to exec the entrypoint binary into the container process |
| `arch_prctl` | Go runtime uses `ARCH_SET_FS` to configure the FS register for goroutine-local storage (TLS) |
| `prctl` | Go runtime sets thread names via `PR_SET_NAME` during scheduler initialization |
| `membarrier` | Go runtime calls this for memory ordering between OS threads during goroutine scheduler init |
| `rseq` | Restartable sequences — registered by the Go runtime since Go 1.21 |
| `set_tid_address` | Go runtime thread initialization |
| `prlimit64` | Go runtime stack size checks at startup |
| `eventfd2` | Go network poller creates its wakeup fd during `netpollinit()` |
| `clone` / `clone3` | OS thread creation for the goroutine scheduler |
| `set_robust_list` | Kernel robust futex list — registered per-thread by the Go runtime |
| `sigaltstack` | Alternate signal stack — set up per-thread by the Go runtime |
| `rt_sigaction` / `rt_sigprocmask` / `rt_sigreturn` | Signal handling for goroutine preemption and panic recovery |

#### Network and I/O (core bouncer functionality)

| Syscall | Reason |
|---|---|
| `socket` / `bind` / `connect` / `listen` / `accept4` | TCP/HTTPS to UniFi controller and CrowdSec LAPI |
| `sendto` / `sendmsg` / `recvfrom` / `recvmsg` | Socket I/O |
| `setsockopt` / `getsockopt` / `getsockname` | Socket configuration |
| `epoll_create1` / `epoll_ctl` / `epoll_pwait` / `epoll_wait` | Go netpoller event loop |
| `read` / `write` / `writev` / `pread64` / `pwrite64` | File and socket reads/writes |
| `openat` / `fstat` / `fstatfs` / `newfstatat` / `statx` / `stat` | File access (bbolt database, config) |
| `flock` / `fsync` / `ftruncate` | bbolt ACID write path |
| `lseek` / `getdents64` / `readlinkat` | bbolt and `/etc/os-release` detection |
| `unlinkat` | bbolt compaction (temp file replacement) |
| `pipe2` | Internal Go runtime wakeup pipes |

#### Memory and scheduling

| Syscall | Reason |
|---|---|
| `mmap` / `mprotect` / `munmap` / `madvise` | Go heap allocator |
| `brk` | Initial heap growth |
| `futex` | Goroutine mutex and channel synchronization |
| `sched_getaffinity` / `sched_yield` | GOMAXPROCS detection and cooperative scheduling |
| `nanosleep` / `clock_gettime` / `gettimeofday` | Timers (decision TTL, rate limiter, batch window) |
| `getrandom` | TLS nonce generation |
| `tgkill` | Go runtime sends signals to specific threads for preemption |
| `exit` / `exit_group` / `restart_syscall` | Process and goroutine teardown |
| `wait4` | Used by Go test runner; inert in production |
| `getpid` / `gettid` | Runtime diagnostics and logging |
| `uname` | OS version detection for LAPI usage-metrics payload |
| `dup` / `dup2` / `dup3` | File descriptor management |
| `fcntl` | File descriptor flags (bbolt, net) |
| `fchmod` | bbolt database file permission hardening |

#### Syscalls intentionally excluded

| Syscall | Why excluded |
|---|---|
| `ptrace` | Debugging/tracing |
| `process_vm_readv` / `process_vm_writev` | Cross-process memory access |
| `perf_event_open` | Performance profiling |
| `kexec_load` | Kernel replacement |
| `mount` / `umount2` | Filesystem mounting |
| `reboot` | System reboot |
| `setuid` / `setgid` / `setgroups` | Privilege escalation — process runs as non-root |
| `chroot` / `pivot_root` | Filesystem root changes |
| `init_module` / `finit_module` | Kernel module loading |

### Validating the profile

The CI `Seccomp Integration Test` job builds the production image and runs:

```bash
docker run --rm \
  --security-opt "seccomp:./security/seccomp-unifi.json" \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --read-only \
  cs-unifi-bouncer-test:ci \
  version
```

The `version` subcommand prints the version string and exits 0. It requires no
network, no UniFi controller, and no CrowdSec. It exercises the full Go runtime
initialization path — the most syscall-dense phase — without needing external
services. A clean exit confirms every syscall needed from process start through
full runtime initialization is present in the allowlist.

### Profile maintenance

If the profile needs updating after a Go version bump or new dependency:

1. Temporarily change `defaultAction` to `SCMP_ACT_LOG` in a local copy
2. Run the production workload for several minutes under normal load
3. Check `journalctl -k --grep=SECCOMP` or `/var/log/syslog` for `type=SECCOMP` audit entries
4. Add any newly required syscalls to the allowlist
5. Revert `defaultAction` to `SCMP_ACT_ERRNO`
6. Validate with the CI test

### Supply Chain Integrity

Every release tag triggers a GitHub Actions workflow that:

1. Builds multi-arch Docker images (`amd64`, `arm64`, `arm/v7`)
2. Runs **Trivy** vulnerability scanning — blocks on `HIGH`/`CRITICAL` unfixed CVEs
3. Signs the image with **Cosign** keyless OIDC (no long-lived signing key)
4. Generates a **CycloneDX SBOM** and attaches it as an OCI attestation
5. Publishes binaries via a **manual binary build matrix** with checksums

To verify a release image:

```bash
# Verify Cosign signature
cosign verify developingchet/cs-unifi-bouncer-pro:latest \
  --certificate-identity-regexp="https://github.com/developingchet/cs-unifi-bouncer-pro/.github/workflows/release.yml" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

# Download and verify SBOM
cosign download attestation developingchet/cs-unifi-bouncer-pro:latest \
  | jq -r '.payload | @base64d | fromjson | .predicate'
```

## Vulnerability Scope

### In Scope

- The Go bouncer binary (`cmd/bouncer/`)
- `Dockerfile` and container configuration
- GitHub Actions workflows (`.github/workflows/`)
- Published Docker images on Docker Hub

### Out of Scope

- CrowdSec LAPI (upstream — report to CrowdSec)
- UniFi controller firmware or API (report to Ubiquiti)
- Denial-of-service attacks requiring access to the metrics/health port (`:9090`, `:8081`)
- Theoretical exploits without a demonstrated attack path

## Dependency Updates

Dependabot is configured to keep Go modules and GitHub Actions up to date. CVE patches in indirect dependencies are addressed on a best-effort basis as they appear in Trivy scans.
