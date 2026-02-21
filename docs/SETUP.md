# Setup Guide

Step-by-step instructions for deploying cs-unifi-bouncer-pro with Docker.

Choose your path below: **quick deploy without cloning** (recommended for most users) or **clone the repository** (recommended for contributors and power users).

---

## Option A: Quick Deploy (No Git Clone)

Pull the compose file, seccomp profile, and you're running in under 2 minutes.

### Prerequisites

| Requirement | Details |
|-------------|---------|
| Docker Engine | 20.10 or later |
| Docker Compose | v2 or later (`docker compose` not `docker-compose`) |
| CrowdSec | 1.4.0 or later, running and accessible |
| UniFi controller | UniFi Network Application 7.x or later |
| UniFi credentials | API key (recommended) or local admin username/password |

Verify CrowdSec is running:

```bash
docker exec crowdsec cscli version
```

### Step 1: Register the Bouncer with CrowdSec

Generate a LAPI key for the bouncer:

```bash
docker exec crowdsec cscli bouncers add unifi-bouncer
```

**Copy the key output — it is only shown once.** If you lose it, delete the bouncer and add it again:

```bash
docker exec crowdsec cscli bouncers delete unifi-bouncer
docker exec crowdsec cscli bouncers add unifi-bouncer
```

### Step 2: Download the Required Files

```bash
curl -O https://raw.githubusercontent.com/developingchet/cs-unifi-bouncer-pro/main/docker-compose.standalone.yml
curl -O https://raw.githubusercontent.com/developingchet/cs-unifi-bouncer-pro/main/security/seccomp-unifi.json
```

### Step 3: Create Your `.env`

```bash
cat > .env <<'EOF'
UNIFI_URL=https://192.168.1.1
UNIFI_API_KEY=your-api-key-here
CROWDSEC_LAPI_KEY=paste-key-from-step-1-here
EOF
chmod 600 .env
```

**Get your UniFi API key** from: **Settings → Control Plane → API Keys**

For all available configuration options, see [CONFIGURATION.md](CONFIGURATION.md).

### Step 4: Start

The bouncer needs to reach both your CrowdSec LAPI and your UniFi controller. Ensure that:
- `CROWDSEC_LAPI_URL` (defaults to `http://crowdsec:8080`) is reachable from inside the bouncer container
- `UNIFI_URL` is reachable from inside the bouncer container

If CrowdSec is in a separate container, you may need to connect them to the same Docker network, or use an IP address instead of a hostname.

### Step 5: Start

```bash
docker compose -f docker-compose.standalone.yml up -d
docker logs -f cs-unifi-bouncer-pro
```

### Step 6: Verify

```bash
# CrowdSec should show the bouncer connected
docker exec crowdsec cscli bouncers list

# Health check
curl -s http://localhost:8081/healthz

# Test with a manual decision
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "setup test"
docker logs -f cs-unifi-bouncer-pro | grep 203.0.113.42
# Clean up
docker exec crowdsec cscli decisions delete --ip 203.0.113.42
```

---

## Option B: Clone the Repository

For contributors, `.env.example` access, or local builds.

### Prerequisites

| Requirement | Details |
|-------------|---------|
| Docker Engine | 20.10 or later |
| Docker Compose | v2 or later (`docker compose` not `docker-compose`) |
| CrowdSec | 1.4.0 or later, running and accessible |
| UniFi controller | UniFi Network Application 7.x or later |
| UniFi credentials | API key (recommended) or local admin username/password |
| Git | Latest stable version |

Verify CrowdSec is running:

```bash
docker exec crowdsec cscli version
```

### Step 1: Register the Bouncer with CrowdSec

Generate a LAPI key for the bouncer:

```bash
docker exec crowdsec cscli bouncers add unifi-bouncer
```

**Copy the key output — it is only shown once.** If you lose it, delete the bouncer and add it again:

```bash
docker exec crowdsec cscli bouncers delete unifi-bouncer
docker exec crowdsec cscli bouncers add unifi-bouncer
```

### Step 2: Clone the Repository

```bash
git clone https://github.com/developingchet/cs-unifi-bouncer-pro.git
cd cs-unifi-bouncer-pro
```

### Step 3: Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` and fill in the required values:

```bash
# Required — UniFi controller
UNIFI_URL=https://192.168.1.1          # Your controller IP or hostname
UNIFI_API_KEY=your-api-key-here        # Preferred over username/password

# Required — CrowdSec LAPI
CROWDSEC_LAPI_URL=http://crowdsec:8080
CROWDSEC_LAPI_KEY=<key from step 1>

# Firewall mode — leave as auto unless you need to force a specific mode
FIREWALL_MODE=auto

# Sites to protect — comma-separated UniFi site names
UNIFI_SITES=default
```

Secure the file so other users cannot read your credentials:

```bash
chmod 600 .env
```

For the full list of configuration options, see [CONFIGURATION.md](CONFIGURATION.md).

#### Using API key authentication (recommended)

UniFi Network ≥ 8.1 supports API key authentication, which is more secure than username/password:

1. In the UniFi console, go to **Settings → Control Plane → API Keys**
2. Create a key with the minimum required permissions (read/write on Firewall)
3. Set `UNIFI_API_KEY` in `.env`

#### Using username/password authentication

For older controllers or where API keys are unavailable:

```bash
UNIFI_USERNAME=admin
UNIFI_PASSWORD=yourpassword
# Leave UNIFI_API_KEY unset or commented out
```

### Step 4: Ensure Network Connectivity

The bouncer must reach **both** your CrowdSec LAPI and your UniFi controller from inside the container.

**For `CROWDSEC_LAPI_URL`**, common values are:
- `http://crowdsec:8080` — if CrowdSec is in Docker Compose and on the same network (no specific network name required — use your default bridge)
- `http://192.168.1.100:8080` — if CrowdSec is on the Docker host, use the host IP
- `http://host.docker.internal:8080` — Docker Desktop trick to reach the host from inside a container

**For `UNIFI_URL`**, similarly ensure it's reachable — typically `https://192.168.1.1` or a hostname like `https://unifi.local`.

If both are on the same Docker network naturally (via docker-compose service names), no additional network configuration is needed. If they are on different networks or different hosts, adjust the URLs accordingly.

### Step 5: Pull the Docker Image

```bash
docker compose pull
```

This pulls the pre-built image from Docker Hub. The image is under 20 MB, runs as
a non-root user in a distroless container, and is Cosign-signed on every release.

> **Building from source** is only needed for development or if you have forked
> the repository. Add `build: .` to the service in `docker-compose.yml` and run
> `docker compose build` instead.

### Step 6: Start the Container

```bash
docker compose up -d
```

The bouncer will:

1. Load and validate configuration
2. Open the bbolt database at `/data/bouncer.db`
3. Connect to the UniFi controller and authenticate
4. Run a startup reconcile (if `FIREWALL_RECONCILE_ON_START=true`)
5. Connect to the CrowdSec LAPI stream and begin processing decisions

### Step 7: Verify Deployment

#### Check container health

```bash
docker ps --filter name=cs-unifi-bouncer-pro
# Status should show "healthy" after the start_period (10 s)
```

#### Check startup logs

```bash
docker logs cs-unifi-bouncer-pro
```

Look for these startup log lines (exact field order may vary):

```json
{"level":"info","version":"1.0.0","msg":"cs-unifi-bouncer-pro starting"}
{"level":"info","sites":["default"],"msg":"ensuring firewall infrastructure"}
{"level":"info","addr":":9090","msg":"Prometheus metrics server started"}
{"level":"info","addr":":8081","msg":"health server started"}
```

If errors appear, check [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

#### Confirm LAPI connectivity

```bash
docker exec crowdsec cscli bouncers list
```

The `last_pull` column for `unifi-bouncer` should show a recent timestamp. It updates every poll interval (default 30 s).

#### Check health endpoints

```bash
curl -s http://localhost:8081/healthz    # Liveness — should return 200 OK
curl -s http://localhost:8081/readyz    # Readiness — should return 200 OK
```

#### Check Prometheus metrics

```bash
curl -s http://localhost:9090/metrics | grep crowdsec_unifi
```

### Step 8: Test with a Manual Decision

Inject a public test IP and confirm the bouncer processes it:

```bash
# Add a test ban
docker exec crowdsec cscli decisions add -i 203.0.113.42 -t ban -d 1h -r "setup test"

# Watch the bouncer logs
docker logs -f cs-unifi-bouncer-pro | grep 203.0.113.42
```

You should see a log line similar to:

```json
{"level":"info","action":"ban","ip":"203.0.113.42","site":"default","msg":"ban applied"}
```

Verify the IP appears in the UniFi firewall group or zone policy, then clean up:

```bash
docker exec crowdsec cscli decisions delete --ip 203.0.113.42
```

---

## Network Scenarios

### Same-host Docker Compose (standard)

Both CrowdSec and the bouncer run on the same host using a shared Docker network. The `CROWDSEC_LAPI_URL` uses the service name as hostname:

```bash
CROWDSEC_LAPI_URL=http://crowdsec:8080
```

### TLS-enabled LAPI

If CrowdSec is configured with TLS:

```bash
CROWDSEC_LAPI_URL=https://crowdsec:8080
CROWDSEC_LAPI_VERIFY_TLS=true
```

### Self-signed certificates (UniFi)

If your UniFi controller uses a self-signed certificate:

```bash
# Option 1: Provide the CA certificate
UNIFI_CA_CERT=/etc/ssl/certs/my-unifi-ca.pem
# Mount the cert in docker-compose.yml: - /path/to/ca.pem:/etc/ssl/certs/my-unifi-ca.pem:ro

# Option 2: Disable TLS verification (NOT recommended for production)
UNIFI_VERIFY_TLS=false
```

### Remote CrowdSec instance

```bash
CROWDSEC_LAPI_URL=http://192.168.1.10:8080
CROWDSEC_LAPI_VERIFY_TLS=false   # or set up TLS
```

### Multiple UniFi sites

```bash
UNIFI_SITES=default,homelab,iot
```

Bans are applied to all listed sites simultaneously.

---

## Updating

```bash
# Pull the latest image
docker compose pull

# Recreate the container
docker compose up -d --force-recreate cs-unifi-bouncer-pro

# Check logs after restart
docker logs cs-unifi-bouncer-pro
```

The startup reconcile (`FIREWALL_RECONCILE_ON_START=true`) automatically syncs the UniFi firewall state with the bbolt database after an update.

---

## Uninstalling

```bash
# Stop and remove the container
docker compose down

# Remove the data volume (this deletes all persistent state)
docker volume rm cs-unifi-bouncer-pro_bouncer-data

# Remove the bouncer registration from CrowdSec
docker exec crowdsec cscli bouncers delete unifi-bouncer
```

To clean up UniFi firewall objects created by the bouncer, run a final reconcile with an empty ban set before removing the bouncer, or delete the managed groups/rules manually from the UniFi console.
