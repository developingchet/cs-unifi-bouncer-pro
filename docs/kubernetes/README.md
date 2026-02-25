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

2. **Create the Secret** — copy `secret.example.yaml`, fill in your values, and apply:
   ```bash
   cp docs/kubernetes/secret.example.yaml my-secret.yaml
   # Edit my-secret.yaml — do NOT commit this file to source control
   kubectl apply -f my-secret.yaml
   ```

3. **Create the PVC** for the bbolt database:
   ```bash
   kubectl apply -f docs/kubernetes/pvc.yaml
   ```

4. **Deploy the bouncer**:
   ```bash
   kubectl apply -f docs/kubernetes/deployment.yaml
   ```

5. **Apply the NetworkPolicy** (recommended — restricts ingress/egress to known ports):
   ```bash
   kubectl apply -f docs/kubernetes/networkpolicy.yaml
   ```

6. **Verify** the pod is running:
   ```bash
   kubectl -n crowdsec get pods -l app=cs-unifi-bouncer-pro
   kubectl -n crowdsec logs -l app=cs-unifi-bouncer-pro -f
   ```

## Hot-Reload

Zone pair configuration can be reloaded without a full pod restart by sending SIGHUP:
```bash
kubectl -n crowdsec exec -it deploy/cs-unifi-bouncer-pro -- kill -HUP 1
```

## Prometheus Scraping

The deployment includes `prometheus.io/scrape: "true"` annotations on the pod template.
If you use the Prometheus Operator, create a `ServiceMonitor` targeting port `9090`.

## Health Endpoints

| Path     | Port | Description                                     |
|----------|------|-------------------------------------------------|
| /healthz | 8081 | Liveness: process is running                    |
| /readyz  | 8081 | Readiness: UniFi controller is reachable (Ping) |
