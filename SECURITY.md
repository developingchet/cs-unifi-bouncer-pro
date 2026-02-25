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

- Connections to the UniFi controller always use TLS (`UNIFI_URL` must be an `https://` address); TLS 1.2 minimum is enforced by the Go TLS stack
- Self-signed certificate support via `UNIFI_CA_CERT` (avoid disabling verification in production)
- HTTP timeouts configured via `UNIFI_HTTP_TIMEOUT` (default 120 s) and `SESSION_REAUTH_TIMEOUT`

#### CrowdSec LAPI transport security

`CROWDSEC_LAPI_URL` accepts both `http://` and `https://` schemes.

- **`https://` is strongly recommended** for any deployment where the bouncer and CrowdSec LAPI are not colocated on the same host. With `https://`, the LAPI key is protected in transit and TLS 1.2 minimum is enforced by the Go TLS stack.
- **`http://` is only safe** when the connection is confined to a loopback address (`127.0.0.1`, `::1`) or a Unix socket — i.e. the LAPI process is on the same host and the connection never crosses a network interface. On a shared container bridge network, `http://` sends the LAPI key in plaintext and exposes it to any process that can observe the network traffic.
- The bouncer emits a **startup warning** when `CROWDSEC_LAPI_URL` uses `http://` with a non-loopback host.

The default value (`http://crowdsec:8080`) is intentionally permissive for local Docker Compose setups where CrowdSec and the bouncer share a private, single-host bridge network. For any other deployment topology — remote LAPI, Kubernetes multi-node, or bare-metal — set `CROWDSEC_LAPI_URL=https://…` and ensure a valid certificate is in place.

## Connectivity Timeout Root Cause (resolved)

Two issues combined to cause a 15-second timeout on UniFi API requests:

1. **IPv6 happy eyeballs stall** — Go's `net.Dialer` with `network="tcp"` races
   IPv4 and IPv6 simultaneously. On hosts with IPv6 interfaces but no IPv6 route
   to the controller, the IPv6 attempt stalls silently for the full 15s timeout.
   Fixed by `ENABLE_IPV6=false` (default) which forces `tcp4` dialing.

2. **Missing `futex_waitv` syscall** — Go 1.21+ uses `futex_waitv` on kernel
   5.16+ as an optimized goroutine park/unpark mechanism. Without it, every
   goroutine yield during network I/O (TLS handshake, waiting for response)
   silently blocks. On kernel 6.8 with Go 1.24 this caused all network operations
   to hang until `http.Client.Timeout` fired at exactly 15 seconds.

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
| `capget` / `capset` | Required by runc at container init to check/set capabilities. Without it the container fails to start with "unable to get capability version" |

#### Network and I/O (core bouncer functionality)

| Syscall | Reason |
|---|---|
| `socket` / `bind` / `connect` / `listen` / `accept4` | TCP/HTTPS to UniFi controller and CrowdSec LAPI |
| `sendto` / `sendmsg` / `recvfrom` / `recvmsg` | Socket I/O |
| `setsockopt` / `getsockopt` / `getsockname` | Socket configuration |
| `getpeername` | Called after `connect()` completes to verify the remote endpoint address |
| `epoll_create1` / `epoll_ctl` / `epoll_pwait` / `epoll_pwait2` / `epoll_wait` | Go netpoller event loop; `epoll_pwait2` is the newer variant (kernel 5.11+) used by Go 1.21+ for scalable async I/O |
| `pselect6` | Go's netpoller fallback selector on systems without epoll support |
| `ppoll` | Netpoller fallback, used alongside `epoll_pwait` |
| `read` / `readv` / `write` / `writev` / `pread64` / `pwrite64` | File and socket reads/writes (vectored and positional variants) |
| `openat` / `fstat` / `fstatfs` / `newfstatat` / `statx` / `stat` | File access (bbolt database, config) |
| `flock` | bbolt acquires `LOCK_EX\|LOCK_NB` advisory lock on `bouncer.db` at open time |
| `fallocate` | bbolt pre-allocates disk space on database creation and growth |
| `fsync` / `fdatasync` / `ftruncate` | bbolt ACID write path; `fdatasync` flushes data faster than full `fsync` |
| `lseek` / `getdents64` / `readlinkat` | bbolt and `/etc/os-release` detection |
| `unlinkat` | bbolt compaction (temp file replacement) |
| `pipe2` | Internal Go runtime wakeup pipes |

#### Memory and scheduling

| Syscall | Reason |
|---|---|
| `mmap` / `mprotect` / `munmap` | Go heap allocator and bbolt mmap mode (database file memory mapping) |
| `madvise` | bbolt calls `madvise(MADV_RANDOM)` after mmap at database open to disable read-ahead |
| `msync` | bbolt flushes dirty mmap pages to disk on every commit using `msync(MS_SYNC)` for ACID guarantees |
| `brk` | Initial heap growth |
| `futex` | Goroutine mutex and channel synchronization |
| `futex_waitv` | Go 1.21+ goroutine scheduler optimization for kernel ≥ 5.16. Used for park/unpark during all I/O waits including TLS. **Root cause of 15s timeout.** |
| `sched_getaffinity` / `sched_yield` | GOMAXPROCS detection and cooperative scheduling |
| `nanosleep` / `clock_gettime` / `clock_nanosleep` / `gettimeofday` | Timers (decision TTL, rate limiter, batch window); `clock_nanosleep` is used by Go runtime timer implementation |
| `timerfd_create` / `timerfd_settime` / `timerfd_gettime` | Go's timer implementation; `timerfd` is the kernel interface backing Go's efficient timer heap |
| `getrandom` | Go `crypto/rand` entropy source; required for TLS client handshakes in both UniFi HTTPS and CrowdSec LAPI connections |
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
