# Kubernetes Deployment

## Prerequisites

- A Kubernetes cluster with a default StorageClass that supports `ReadWriteOnce` PVCs.
- The `crowdsec` namespace (or adjust the `namespace:` fields in all manifests).

## Single-Replica Constraint

> **Important:** `replicas: 1` is mandatory. bbolt (the embedded database) does not support
> concurrent writers. Running two instances simultaneously will corrupt the database.
>
> The deployment uses `strategy: Recreate` to ensure the old pod is fully terminated before
> the new one starts during a rollout. Do **not** change this to `RollingUpdate`.

## Deployment

1. **Create the namespace** (if it does not exist):
   ```bash
   kubectl create namespace crowdsec
   ```

2. **Create the Secret and ConfigMap** — copy `secret.example.yaml`, fill in your values, and apply:
   ```bash
   cp docs/kubernetes/secret.example.yaml my-secret.yaml
   # Edit my-secret.yaml — do NOT commit this file to source control
   kubectl apply -f my-secret.yaml
   ```
   The file holds two objects. The Secret carries the four credentials
   (`UNIFI_API_KEY`, `UNIFI_USERNAME`, `UNIFI_PASSWORD`, `CROWDSEC_LAPI_KEY`);
   the Deployment mounts it at `/run/secrets/cs-unifi-bouncer-pro` and points
   the matching `*_FILE` settings at the files, so the credentials never appear
   in the container environment. Keep all four keys and leave the ones you do
   not use empty. The ConfigMap carries the other settings (`UNIFI_URL`,
   `CROWDSEC_LAPI_URL`, `ZONE_PAIRS`, and so on) as environment variables; add
   further non-secret settings there.

3. **Create the PVC** for the bbolt database:
   ```bash
   kubectl apply -f docs/kubernetes/pvc.yaml
   ```

4. **Deploy the bouncer**:
   ```bash
   kubectl apply -f docs/kubernetes/deployment.yaml
   ```

5. **Apply the NetworkPolicy** (recommended — restricts ingress/egress to known peers and ports). It contains placeholders that must be adjusted first, each marked `Adjust` in the file:
   - the namespace allowed to scrape the metrics port (default: `monitoring`);
   - the controller address (`ipBlock` `192.168.1.1/32`, which must match `UNIFI_URL`) and port, 443 for UniFi OS or 8443 for a self-hosted Network Application;
   - the labels of the CrowdSec LAPI pods, or an `ipBlock` for a LAPI outside the cluster;
   - the labels of the cluster DNS pods, if they are not `k8s-app: kube-dns` in `kube-system`.

   ```bash
   kubectl apply -f docs/kubernetes/networkpolicy.yaml
   ```
   A blocked controller shows as `connection refused` or a timeout in the logs and `/readyz` returns 503. Optional features that fetch from the internet (`BLOCKLIST_URLS`, `ABUSEIPDB_LIST`, `CLOUDFLARE_WHITELIST_ENABLED`, `WEBHOOK_URL`) need egress rules of their own. Only the metrics port accepts ingress; kubelet probes are not affected on CNIs that exempt node traffic from NetworkPolicy.

6. **Verify** the pod is running:
   ```bash
   kubectl -n crowdsec get pods -l app=cs-unifi-bouncer-pro
   kubectl -n crowdsec logs -l app=cs-unifi-bouncer-pro -f
   ```

## Configuration Reload

Restart the pod after changing its Secret or ConfigMap. Kubernetes refreshes mounted Secret files in place, but the bouncer reads them only at startup:
```bash
kubectl -n crowdsec rollout restart deployment/cs-unifi-bouncer-pro
```

## Prometheus Scraping

The deployment includes `prometheus.io/scrape: "true"` annotations on the pod template.
If you use the Prometheus Operator, create a `ServiceMonitor` targeting port `9090`.
The NetworkPolicy admits scrapes only from the `monitoring` namespace; change its `namespaceSelector` if Prometheus runs elsewhere.

## Resources and Hardening

The container limit is 512Mi. A periodic resync (`CROWDSEC_RESYNC_INTERVAL`) reads the whole LAPI decision list into memory, accepting a response of up to 256 MiB, and then decodes it, so the limit has to stay above that cap; raise it for lists that approach it.

The pod runs with the runtime default seccomp profile, a read-only root filesystem, no capabilities, and no Kubernetes API token (`automountServiceAccountToken: false`).

## Health Endpoints

| Path     | Port | Description                                     |
|----------|------|-------------------------------------------------|
| /healthz | 8081 | Liveness: process is running                    |
| /readyz  | 8081 | Readiness: first LAPI batch processed, UniFi controller reachable (Ping) |

The pod stays unready until the first LAPI pull has been processed, which can take several minutes on a large ban list. The manifest raises `progressDeadlineSeconds` to 1200 so `kubectl rollout status` does not report a stalled rollout meanwhile; raise it, and any `helm --wait` or GitOps health timeout, further for larger lists.

`/status/db` on the same port serves the ban database to `kubectl exec … status` inside the pod; it refuses requests without the token in `DATA_DIR/status.token`, so it does not need a Service port.
