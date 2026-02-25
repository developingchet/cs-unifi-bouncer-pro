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
   ```

## Hot-Reload (SIGHUP)

To reload zone pair configuration without restarting the daemon:
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

The unit file enables a comprehensive set of systemd hardening options:

- `DynamicUser=yes` — a transient UID/GID is allocated at service start; no persistent user account is required.
- `CapabilityBoundingSet=` (empty) — drops all Linux capabilities; the bouncer needs none.
- `ProtectSystem=strict` — mounts the OS filesystem read-only (except `StateDirectory` and `TmpFiles`).
- `NoNewPrivileges=yes` — prevents privilege escalation via `setuid`/`setgid` binaries.
- `RestrictAddressFamilies=AF_INET AF_INET6` — only IPv4/IPv6 sockets are allowed.

## Verifying the Unit File

```bash
systemd-analyze verify /etc/systemd/system/cs-unifi-bouncer-pro.service
```
