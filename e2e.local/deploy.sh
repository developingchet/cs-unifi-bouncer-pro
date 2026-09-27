#!/usr/bin/env bash
# Live deployment matrix: runs the deployment artifacts the repo ships against
# the e2e stack, as a user would, and checks each one enforces a ban.
#
#   compose     docker-compose.yml as shipped (image and network overridden)
#   standalone  docker-compose.standalone.yml as shipped
#   published   docker-compose.yml with the published :latest image
#   k8s         docs/kubernetes/* on k3s running in a container
#   systemd     docs/systemd unit under systemd running in a container
#
# Needs a running stack (bash e2e.local/up.sh). The e2e bouncer is stopped while
# a deployment runs, since both would manage the same controller objects.
#
#   bash e2e.local/deploy.sh                 every section
#   bash e2e.local/deploy.sh k8s             just this one
set -u
cd "$(dirname "$0")"
. ./lib.sh
single_run
trap 'rm -f .run.pid' EXIT

ROOT=..
WORK=.deploy
NET=csue2e_e2e
SVC=cs-unifi-bouncer-pro
K3S_IMAGE=${K3S_IMAGE:-rancher/k3s:v1.33.1-k3s1}
K3S=csue2e-k3s
OCTET=$(( (RANDOM % 200) + 20 ))  # a fresh address per run, so a ban is new

dstate()  { docker inspect -f "$1" "$SVC" 2>/dev/null; }
dhealth() { [ "$(dstate '{{.State.Health.Status}}')" = healthy ]; }
dready()  { [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/readyz)" = 200 ]; }

# write_env <dir> writes the .env a user would create for the e2e stack.
write_env() {
  cat > "$1/.env" <<EOF
UNIFI_URL=https://unifi:8443
UNIFI_API_KEY=
UNIFI_USERNAME=e2eadmin
UNIFI_PASSWORD=$UNIFI_PASS
UNIFI_VERIFY_TLS=false
CROWDSEC_LAPI_URL=http://crowdsec:8080
CROWDSEC_LAPI_ALLOW_HTTP=true
CROWDSEC_LAPI_KEY=$LAPI_KEY
EOF
}

# override <dir> [image] [extra environment lines] joins the stack's network
# and optionally swaps the image or adds environment entries.
override() {
  {
    echo "services:"
    echo "  $SVC:"
    [ -n "${2:-}" ] && echo "    image: $2"
    echo "    networks: [e2e]"
    if [ -n "${3:-}" ]; then echo "    environment:"; printf '%s\n' "$3"; fi
    echo "networks:"
    echo "  e2e:"
    echo "    external: true"
    echo "    name: $NET"
  } > "$1/override.yml"
}

# compose_checks <label> <compose command...>: the checks every Docker
# deployment must pass. The stack is left down with its volume kept.
compose_checks() {
  local label=$1; shift
  local ip=198.19.20.$OCTET
  "$@" up -d >/dev/null 2>&1 || { bad "[$label] compose up"; "$@" logs 2>&1 | tail -5; return 1; }
  wait_for 120 "[$label] container reports healthy (compose healthcheck)" dhealth || { docker logs "$SVC" 2>&1 | tail -5; return 1; }
  check "[$label] /readyz on 127.0.0.1:8081" dready
  check "[$label] metrics on 127.0.0.1:9090" sh -c "curl -s http://127.0.0.1:9090/metrics | grep -q '^crowdsec_unifi_active_bans'"
  [ "$(dstate '{{.HostConfig.ReadonlyRootfs}}')" = true ] && ok "[$label] read-only root filesystem" || bad "[$label] root filesystem writable"
  dstate '{{json .HostConfig.CapDrop}}' | grep -q ALL && ok "[$label] all capabilities dropped" || bad "[$label] capabilities kept"
  dstate '{{json .HostConfig.SecurityOpt}}' | grep -q seccomp && dstate '{{json .HostConfig.SecurityOpt}}' | grep -q no-new-privileges \
    && ok "[$label] seccomp profile and no-new-privileges applied" || bad "[$label] security options: $(dstate '{{json .HostConfig.SecurityOpt}}')"
  [ "$(dstate '{{.Config.User}}')" != "" ] && [ "$(dstate '{{.Config.User}}')" != root ] && [ "$(dstate '{{.Config.User}}')" != 0 ] \
    && ok "[$label] runs as non-root user $(dstate '{{.Config.User}}')" || bad "[$label] runs as '$(dstate '{{.Config.User}}')'"
  decide "$ip"
  wait_for 60 "[$label] a new ban reaches the controller" has_ip v4 "$ip"
  check "[$label] no seccomp denial in logs" sh -c "! docker logs $SVC 2>&1 | grep -qiE 'operation not permitted|bad system call'"
  groups_before=$(group_count v4)
  "$@" down >/dev/null 2>&1
  "$@" up -d >/dev/null 2>&1
  wait_for 120 "[$label] healthy again after down/up (volume kept)" dhealth
  check "[$label] ban kept across the restart" has_ip v4 "$ip"
  [ "$(group_count v4)" = "$groups_before" ] && ok "[$label] no duplicate groups after restart" || bad "[$label] v4 groups $groups_before -> $(group_count v4)"
  docker stop -t 40 "$SVC" >/dev/null
  [ "$(dstate '{{.State.ExitCode}}')" = 0 ] && ok "[$label] SIGTERM exits 0" || bad "[$label] exit code $(dstate '{{.State.ExitCode}}')"
  undecide "$ip"
}

sec_compose() {
  step "K1. docker-compose.yml as shipped"
  rm -rf "$WORK/compose"; mkdir -p "$WORK/compose/security"
  cp "$ROOT/docker-compose.yml" "$WORK/compose/"
  cp "$ROOT/security/seccomp-unifi.json" "$WORK/compose/security/"
  write_env "$WORK/compose"
  override "$WORK/compose" cs-unifi-bouncer-pro:e2e
  $DC stop bouncer >/dev/null 2>&1
  local dcc=(docker compose -p csue2e-deploy --project-directory "$WORK/compose" -f "$WORK/compose/docker-compose.yml" -f "$WORK/compose/override.yml")
  compose_checks compose "${dcc[@]}"
  "${dcc[@]}" down -v >/dev/null 2>&1
}

sec_standalone() {
  step "K2. docker-compose.standalone.yml as shipped"
  rm -rf "$WORK/standalone"; mkdir -p "$WORK/standalone"
  cp "$ROOT/docker-compose.standalone.yml" "$ROOT/security/seccomp-unifi.json" "$WORK/standalone/"
  write_env "$WORK/standalone"
  $DC stop bouncer >/dev/null 2>&1
  local dcs=(docker compose -p csue2e-deploy --project-directory "$WORK/standalone" -f "$WORK/standalone/docker-compose.standalone.yml" -f "$WORK/standalone/override.yml")
  # The file passes only its listed variables: without an API key the
  # bouncer must refuse to start and say which credentials it needs.
  override "$WORK/standalone" cs-unifi-bouncer-pro:e2e
  "${dcs[@]}" up -d >/dev/null 2>&1
  sleep 8
  docker logs "$SVC" 2>&1 | grep -q "UNIFI_API_KEY or both UNIFI_USERNAME and UNIFI_PASSWORD are required" \
    && ok "[standalone] without an API key, startup names the missing credentials" || bad "[standalone] $(docker logs "$SVC" 2>&1 | tail -2)"
  "${dcs[@]}" down -v >/dev/null 2>&1
  # Uncommenting the optional lines, as the file tells password users to.
  override "$WORK/standalone" cs-unifi-bouncer-pro:e2e "$(printf '      - %s\n' \
    UNIFI_USERNAME=e2eadmin "UNIFI_PASSWORD=$UNIFI_PASS" UNIFI_VERIFY_TLS=false \
    CROWDSEC_LAPI_URL=http://crowdsec:8080 CROWDSEC_LAPI_ALLOW_HTTP=true)"
  compose_checks standalone "${dcs[@]}"
  "${dcs[@]}" down -v >/dev/null 2>&1
}

sec_published() {
  step "K3. Published image developingchet/cs-unifi-bouncer-pro:latest"
  docker pull -q developingchet/cs-unifi-bouncer-pro:latest >/dev/null 2>&1 || { skip "cannot pull the published image"; return; }
  echo "  $(docker run --rm developingchet/cs-unifi-bouncer-pro:latest version 2>&1 | head -1)"
  rm -rf "$WORK/published"; mkdir -p "$WORK/published/security"
  cp "$ROOT/docker-compose.yml" "$WORK/published/"
  cp "$ROOT/security/seccomp-unifi.json" "$WORK/published/security/"
  write_env "$WORK/published"
  override "$WORK/published"
  $DC stop bouncer >/dev/null 2>&1
  local dcp=(docker compose -p csue2e-deploy --project-directory "$WORK/published" -f "$WORK/published/docker-compose.yml" -f "$WORK/published/override.yml")
  compose_checks published "${dcp[@]}"
  "${dcp[@]}" down -v >/dev/null 2>&1
}

kc() { kubectl --kubeconfig "$WORK/kubeconfig" "$@"; }
kready() { [ "$(kc -n crowdsec get pod -l app=$SVC -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null)" = true ]; }
node_ready() { kc get nodes 2>/dev/null | grep -q ' Ready'; }
container_ip() { docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$1"; }

sec_k8s() {
  step "K4. docs/kubernetes on k3s"
  mkdir -p "$WORK/k8s"
  docker rm -f "$K3S" >/dev/null 2>&1
  docker run -d --privileged --name "$K3S" --network "$NET" -p 127.0.0.1:16443:6443 "$K3S_IMAGE" \
    server --disable=traefik --disable=metrics-server --tls-san 127.0.0.1 >/dev/null
  wait_for 120 "k3s kubeconfig written" docker exec "$K3S" test -s /etc/rancher/k3s/k3s.yaml || return
  docker exec "$K3S" cat /etc/rancher/k3s/k3s.yaml | sed 's#https://127.0.0.1:6443#https://127.0.0.1:16443#' > "$WORK/kubeconfig"
  wait_for 180 "k3s node Ready" node_ready || return
  docker save cs-unifi-bouncer-pro:e2e | docker exec -i "$K3S" ctr images import - >/dev/null \
    && ok "bouncer image imported into k3s" || { bad "image import"; return; }

  # Cluster DNS cannot see the compose network's names, so use addresses.
  local unifi_ip crowdsec_ip ip=198.19.21.$OCTET
  unifi_ip=$(container_ip csue2e-unifi-1); crowdsec_ip=$(container_ip csue2e-crowdsec-1)
  kc create namespace crowdsec >/dev/null
  sed -e "s#UNIFI_URL: .*#UNIFI_URL: \"https://$unifi_ip:8443\"#" \
      -e 's#UNIFI_USERNAME: .*#UNIFI_USERNAME: "e2eadmin"#' \
      -e "s#UNIFI_PASSWORD: .*#UNIFI_PASSWORD: \"$UNIFI_PASS\"#" \
      -e 's#UNIFI_VERIFY_TLS: .*#UNIFI_VERIFY_TLS: "false"#' \
      -e "s#CROWDSEC_LAPI_URL: .*#CROWDSEC_LAPI_URL: \"http://$crowdsec_ip:8080\"\n  CROWDSEC_LAPI_ALLOW_HTTP: \"true\"#" \
      -e "s#CROWDSEC_LAPI_KEY: .*#CROWDSEC_LAPI_KEY: \"$LAPI_KEY\"#" \
      "$ROOT/docs/kubernetes/secret.example.yaml" > "$WORK/k8s/secret.yaml"
  sed -e 's#image: developingchet/cs-unifi-bouncer-pro:.*#image: cs-unifi-bouncer-pro:e2e#' \
      "$ROOT/docs/kubernetes/deployment.yaml" > "$WORK/k8s/deployment.yaml"
  $DC stop bouncer >/dev/null 2>&1
  kc apply -f "$WORK/k8s/secret.yaml" -f "$ROOT/docs/kubernetes/pvc.yaml" \
    -f "$ROOT/docs/kubernetes/networkpolicy.yaml" -f "$WORK/k8s/deployment.yaml" >/dev/null \
    && ok "manifests apply (secret from secret.example.yaml, pvc, networkpolicy, deployment)" || { bad "kubectl apply"; return; }

  if wait_for 180 "pod Ready with the shipped NetworkPolicy (readiness probe)" kready; then :; else
    echo "  pod log: $(kc -n crowdsec logs deploy/$SVC --tail=3 2>&1 | cut -c1-200)"
  fi
  if ! kready; then
    return
  fi
  # The pod can start before the policy is enforced; readiness only counts
  # once the controller is reachable under it.
  sleep 30
  check "pod still Ready 30s later (controller reachable under the policy)" kready
  check "no controller ping failures" sh -c "! kubectl --kubeconfig $WORK/kubeconfig -n crowdsec logs deploy/$SVC --since=25s 2>&1 | grep -q 'controller ping failed'"
  [ "$(kc -n crowdsec get pod -l app=$SVC -o jsonpath='{.items[0].spec.containers[0].securityContext.runAsUser}')" = 65532 ] \
    && ok "runs as uid 65532 with a read-only root filesystem" || bad "securityContext not applied"
  check "in-pod healthcheck subcommand" kc -n crowdsec exec deploy/$SVC -- /cs-unifi-bouncer-pro healthcheck
  decide "$ip"
  wait_for 60 "a new ban reaches the controller from the pod" has_ip v4 "$ip"
  kc -n crowdsec rollout restart deployment/$SVC >/dev/null
  kc -n crowdsec rollout status deployment/$SVC --timeout=180s >/dev/null && ok "Recreate rollout completes" || bad "rollout"
  wait_for 120 "restarted pod Ready" kready
  check "ban kept across the restart (PVC)" has_ip v4 "$ip"
  check "restarted pod opened the existing database (no startup errors)" sh -c "! kubectl --kubeconfig $WORK/kubeconfig -n crowdsec logs deploy/$SVC 2>&1 | grep -q '\"level\":\"error\"'"
  undecide "$ip"
}

k8s_down() { docker rm -f "$K3S" >/dev/null 2>&1; }

SYSD=csue2e-systemd
SYSD_IMAGE=${SYSD_IMAGE:-jrei/systemd-debian:12}
sx()      { docker exec "$SYSD" "$@"; }
sactive() { [ "$(sx systemctl is-active $SVC 2>/dev/null)" = active ]; }
sready()  { sx /usr/local/bin/$SVC healthcheck >/dev/null 2>&1; }
sjournal() { sx journalctl -u $SVC --no-pager 2>&1; }

sec_systemd() {
  step "K5. docs/systemd unit under systemd"
  local ip=198.19.22.$OCTET cid out
  rm -rf "$WORK/systemd"; mkdir -p "$WORK/systemd"
  cid=$(docker create cs-unifi-bouncer-pro:e2e)
  docker cp "$cid:/cs-unifi-bouncer-pro" "$WORK/systemd/$SVC" >/dev/null; docker rm "$cid" >/dev/null
  write_env "$WORK/systemd"
  docker rm -f "$SYSD" >/dev/null 2>&1
  docker run -d --name "$SYSD" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --network "$NET" "$SYSD_IMAGE" >/dev/null || { bad "start systemd container"; return; }
  wait_for 60 "systemd running in the container" sh -c "docker exec $SYSD systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded'" || return
  docker cp "$WORK/systemd/$SVC" "$SYSD:/usr/local/bin/$SVC" >/dev/null
  sx chmod 755 /usr/local/bin/$SVC
  sx mkdir -p /etc/$SVC
  docker cp "$WORK/systemd/.env" "$SYSD:/etc/$SVC/bouncer.env" >/dev/null
  sx chmod 600 /etc/$SVC/bouncer.env
  docker cp "$ROOT/docs/systemd/$SVC.service" "$SYSD:/etc/systemd/system/$SVC.service" >/dev/null
  sx chmod 644 /etc/systemd/system/$SVC.service
  # ExecReload uses /bin/kill from procps, which every full distribution ships
  # and this minimal image lacks.
  sx sh -c "test -x /bin/kill || (apt-get update -qq && apt-get install -y -qq procps)" >/dev/null 2>&1
  out=$(sx systemd-analyze verify /etc/systemd/system/$SVC.service 2>&1) && ok "systemd-analyze verify clean" \
    || bad "verify: $(echo "$out" | tail -3 | tr '\n' ' ')"
  $DC stop bouncer >/dev/null 2>&1
  sx systemctl daemon-reload
  sx systemctl enable --now $SVC >/dev/null 2>&1
  wait_for 90 "service active and ready (healthcheck subcommand)" sready \
    || { echo "  journal: $(sjournal | tail -5 | cut -c1-200)"; }
  local pid uid
  pid=$(sx systemctl show -p MainPID --value $SVC)
  uid=$(sx stat -c %u "/proc/$pid" 2>/dev/null)
  [ -n "$uid" ] && [ "$uid" != 0 ] && ok "runs as dynamic uid $uid" || bad "main pid $pid uid '$uid'"
  decide "$ip"
  wait_for 60 "a new ban reaches the controller" has_ip v4 "$ip"
  sx systemctl reload $SVC
  sleep 3
  check "systemctl reload keeps the service active" sactive
  check "reload delivered SIGHUP" sh -c "docker exec $SYSD journalctl -u $SVC --no-pager | grep -q 'SIGHUP'"
  sx systemctl restart $SVC
  wait_for 90 "ready after restart" sready
  check "database in the StateDirectory" sx test -s /var/lib/$SVC/bouncer.db
  check "ban kept across the restart" has_ip v4 "$ip"
  check "no sandbox denials in the journal" sh -c "! docker exec $SYSD journalctl -u $SVC --no-pager | grep -qiE 'operation not permitted|bad system call|permission denied'"
  sx systemctl stop $SVC
  check "stop is clean (Result=success)" sh -c "docker exec $SYSD systemctl show -p Result --value $SVC | grep -qx success"
  undecide "$ip"
  docker rm -f "$SYSD" >/dev/null 2>&1
}

# "published" is not in the default list: v1.2.5 and earlier cannot log in to a
# self-hosted controller like the e2e one. Run it by name after a release.
SECTIONS=${*:-compose standalone k8s systemd}
$DC build bouncer >/dev/null 2>&1 || { echo "bouncer build failed"; exit 1; }
for s in $SECTIONS; do "sec_$s"; done
k8s_down
docker rm -f "$SVC" >/dev/null 2>&1
$DC up -d bouncer >/dev/null 2>&1
wait_for 90 "default bouncer ready at the end" ready
echo
echo "DEPLOY RESULT: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
