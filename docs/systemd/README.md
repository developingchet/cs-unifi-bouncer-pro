# systemd Unit File

## Installation

1. **Copy the binary** to `/usr/local/bin/`:
   ```bash
   sudo cp cs-unifi-bouncer-pro /usr/local/bin/
   sudo chmod +x /usr/local/bin/cs-unifi-bouncer-pro
   ```

2. **Create the configuration directory** and environment file:
   ```bash
   sudo mkdir -p /etc/cs-unifi-bouncer-pro
   sudo cp .env.example /etc/cs-unifi-bouncer-pro/bouncer.env
   sudo chmod 600 /etc/cs-unifi-bouncer-pro/bouncer.env
   # Edit the file and fill in UNIFI_URL, credentials, CROWDSEC_LAPI_KEY, etc.
   sudo nano /etc/cs-unifi-bouncer-pro/bouncer.env
   ```

3. **Install the unit file**:
   ```bash
   sudo cp docs/systemd/cs-unifi-bouncer-pro.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

4. **Enable and start** the service:
   ```bash
   sudo systemctl enable --now cs-unifi-bouncer-pro
   ```

5. **Verify** it started successfully:
   ```bash
   sudo systemctl status cs-unifi-bouncer-pro
   sudo journalctl -u cs-unifi-bouncer-pro -f
   cs-unifi-bouncer-pro healthcheck   # probes /healthz on HEALTH_ADDR
   ```

   `healthcheck` reads `HEALTH_ADDR` from the calling shell, not from the unit,
   and probes port 8081 when it is unset. If you changed the port, export the
   same `HEALTH_ADDR` first.

## Listen Addresses

The unit sets `HEALTH_ADDR=127.0.0.1:8081` and `METRICS_ADDR=127.0.0.1:9090`, so
both endpoints are reachable from the host only. Without these settings the
program listens on all interfaces, which is the right default inside a
container but exposes the endpoints to the network on a host. `/readyz` checks
the controller, so it should not be reachable by untrusted clients.

To let a remote Prometheus scrape the metrics, set `METRICS_ADDR` in
`/etc/cs-unifi-bouncer-pro/bouncer.env` (the environment file overrides the
unit), for example `METRICS_ADDR=192.168.1.10:9090`, and restrict access to
that port with a host firewall. The two addresses must differ while metrics
are enabled.

## Hot-Reload (SIGHUP)

To reload the zone pairs (`ZONE_PAIRS`, `EGRESS_ZONE_PAIRS`) without restarting the daemon:
```bash
sudo systemctl reload cs-unifi-bouncer-pro
# or equivalently:
sudo kill -HUP $(systemctl show -p MainPID --value cs-unifi-bouncer-pro)
```

`ExecReload=/bin/kill -HUP $MAINPID` maps directly to the bouncer's SIGHUP handler.

## State Directory

The bbolt database is stored in `/var/lib/cs-unifi-bouncer-pro/` (created automatically
by `StateDirectory=cs-unifi-bouncer-pro`). This directory is owned by the dynamic user
created by `DynamicUser=yes`.

## Security Notes

The unit file sets these hardening options:

| Directive | Effect |
|-----------|--------|
| `DynamicUser=yes` | A transient UID/GID is allocated at service start; no persistent user account is required |
| `CapabilityBoundingSet=` (empty), `AmbientCapabilities=` (empty) | All Linux capabilities dropped; the bouncer needs none |
| `NoNewPrivileges=yes` | No privilege escalation via `setuid`/`setgid` binaries |
| `PrivateTmp=yes` | Private `/tmp` |
| `PrivateDevices=yes` | No access to raw device nodes |
| `ProtectSystem=strict` | The OS filesystem is read-only, except the state directory and the private `/tmp` |
| `ProtectHome=yes` | Home directories inaccessible |
| `ProtectProc=invisible`, `ProcSubset=pid` | Other processes' `/proc` entries and the non-process parts of `/proc` are hidden |
| `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes` | `/proc/sys` and similar paths read-only, no module loading, no kernel log access |
| `ProtectControlGroups=yes` | cgroup filesystem read-only |
| `ProtectClock=yes`, `ProtectHostname=yes` | No clock or hostname changes |
| `RestrictAddressFamilies=AF_INET AF_INET6` | Only IPv4/IPv6 sockets are allowed |
| `RestrictNamespaces=yes` | Namespace creation blocked |
| `LockPersonality=yes` | ABI personality locked |
| `MemoryDenyWriteExecute=yes` | No writable and executable memory mappings |
| `RestrictRealtime=yes` | Real-time scheduling blocked |
| `UMask=0077` | Files the service creates, such as the database, are readable by its own user only |
| `SystemCallArchitectures=native` | System calls of other ABIs, such as 32-bit on a 64-bit host, are refused |
| `SystemCallFilter=@system-service`, `SystemCallErrorNumber=EPERM` | System calls outside the service set fail with `EPERM` |

`ProtectProc=` and `ProcSubset=` need systemd 247 or newer. On an older release, remove those two lines; systemd 242 and later accept the rest.

## Verifying the Unit File

```bash
systemd-analyze verify /etc/systemd/system/cs-unifi-bouncer-pro.service
```
