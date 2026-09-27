# Shared helpers for run.sh and settings.sh. Source it from e2e.local/.
# shellcheck shell=bash
export MSYS_NO_PATHCONV=1

DC="docker compose --profile bouncer"
LAPI_KEY=e2e-lapi-key-0123456789abcdef
UNIFI_PASS=E2e-Admin-Pass-123
FEED_TOKEN=e2e-feed-token
SITE=default
PASS=0; FAIL=0; SKIP=0

ok()   { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP: $*"; SKIP=$((SKIP+1)); }
step() { echo; echo "== $* =="; }
check() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

# wait_for <timeout-seconds> <description> <command...>
wait_for() {
  local t=$1 d=$2; shift 2
  for _ in $(seq 1 "$t"); do
    if "$@" >/dev/null 2>&1; then ok "$d"; return 0; fi
    sleep 1
  done
  bad "$d (timed out after ${t}s)"; return 1
}

# single_run refuses a second concurrent run: a leftover run whose parent was
# killed tears the shared compose project down underneath the other.
single_run() {
  if [ -f .run.pid ] && kill -0 "$(cat .run.pid)" 2>/dev/null; then
    echo "another e2e run is active (pid $(cat .run.pid)); stop it first" >&2
    exit 3
  fi
  echo $$ > .run.pid
}

api()      { bash ./api.sh "$@"; }
q()        { node ./q.js "$1"; }
groups()   { api GET "/api/s/$SITE/rest/firewallgroup"; }
rules()    { api GET "/api/s/$SITE/rest/firewallrule"; }
# managed_members <family> [prefix]: every IP in <prefix>-<family>-* groups, one per line
managed_members() { groups | q "data.filter(g => g.name.startsWith('${2:-crowdsec-block}-$1-')).flatMap(g => g.group_members)"; }
has_ip()     { managed_members "$1" | grep -qx "$2"; }
lacks_ip()   { ! has_ip "$1" "$2"; }
group_count() { groups | q "data.filter(g => g.name.startsWith('crowdsec-block-$1-')).length"; }
rule_count()  { rules | q "data.filter(r => r.name.startsWith('crowdsec-drop-$1-')).length"; }
decide()   { $DC exec -T crowdsec cscli decisions add -i "$1" -d "${2:-1h}" -R "${3:-e2e test}" >/dev/null; }
undecide() { $DC exec -T crowdsec cscli decisions delete -i "$1" >/dev/null; }
health()   { curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:18081/$1"; }
healthy()  { [ "$(health healthz)" = 200 ]; }
ready()    { [ "$(health readyz)" = 200 ]; }
metrics()  { curl -s http://127.0.0.1:19090/metrics; }
metric()   { local v; v=$(metrics | grep -F "$1" | grep -v '^#' | head -1 | sed 's/.* //'); echo "${v:-0}"; }
blogs()    { $DC logs bouncer --no-log-prefix 2>&1; }
bexec()    { $DC exec -T bouncer /cs-unifi-bouncer-pro "$@"; }
webhooks() { curl -s http://127.0.0.1:18080/_webhooks; }
# save_logs appends the current bouncer container's logs, which a recreate discards.
save_logs() { blogs >> bouncer.log; }
restart_bouncer() { save_logs; $DC up -d --force-recreate bouncer >/dev/null 2>&1; wait_for 90 "$1" ready; }
offline()  { $DC run --rm -T bouncer "$@"; }

# stack_up builds and starts every service and completes the controller's
# first-run wizard. The bouncer itself is left to the caller.
stack_up() {
  $DC down -v --remove-orphans >/dev/null 2>&1
  rm -f .cookies bouncer.log
  $DC up -d --build unifi-db unifi crowdsec mock >/dev/null 2>&1 || { echo "compose up failed"; $DC logs --tail 50; exit 1; }
  wait_for 300 "UniFi Network Application answers /status" curl -skf https://127.0.0.1:18443/status
  version=$(curl -sk https://127.0.0.1:18443/status | q 'd.meta.server_version')
  echo "  UniFi Network Application $version"
  bash ./setup-unifi.sh >/dev/null && ok "controller first-run setup completed headlessly" || { bad "controller setup"; exit 1; }
}

# --- settings matrix: run the bouncer as a one-off container with extra
# docker args (-e K=V, -p, -v). Ports 18081/19090 are published as usual.
CASE=csue2e-case
CASE_NAME=none
case_rm()      { docker rm -f "$CASE" >/dev/null 2>&1; }
case_logs()    { docker logs "$CASE" 2>&1; }
case_running() { [ "$(docker inspect -f '{{.State.Running}}' "$CASE" 2>/dev/null)" = true ]; }
case_exit()    { docker inspect -f '{{.State.ExitCode}}' "$CASE" 2>/dev/null; }
case_log_has() { case_logs | grep -qF -- "$1"; }
case_log_lacks() { ! case_log_has "$1"; }
# case_up <name> [docker run args...]: stops the compose bouncer and starts the case.
case_up() {
  CASE_NAME=$1; shift
  $DC stop bouncer >/dev/null 2>&1
  case_rm
  # compose refuses --service-ports together with -p, so a case that
  # publishes its own ports publishes all of them.
  local ports=--service-ports a
  for a in "$@"; do [ "$a" = -p ] && ports=; done
  $DC run -d $ports --name "$CASE" "$@" bouncer >/dev/null 2>&1
}
# case_down stops the case with SIGTERM and keeps its logs under cases/.
case_down() {
  mkdir -p cases
  docker stop -t 40 "$CASE" >/dev/null 2>&1
  case_logs > "cases/$CASE_NAME.log"
  case_rm
}
# rejects <description> <expected error text> [docker run args...]: the
# setting must make `validate` fail with that text.
rejects() {
  local d=$1 want=$2 out rc; shift 2
  out=$($DC run --rm -T "$@" bouncer validate 2>&1); rc=$?
  if [ $rc != 0 ] && echo "$out" | grep -qF -- "$want"; then ok "$d"
  else bad "$d (rc=$rc): $(echo "$out" | tail -2 | tr '\n' ' ')"; fi
}
