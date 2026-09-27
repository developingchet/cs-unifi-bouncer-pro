#!/usr/bin/env bash
# Opt-in zone-mode e2e against a real UniFi OS console (UDM).
#
#   E2E_UDM_CONFIRM=yes bash e2e.local/udm.sh
#
# Scope: one zone pair (E2E_UDM_PAIR, default "Test A->Test B") on one site.
# Every object this run creates is named with a unique run prefix (e2e-<id>-)
# and tagged with a run-specific description. The script itself only PUTs or
# DELETEs objects whose name carries that prefix, re-reading the name first;
# everything else is read. Cleanup (drain, then prefix sweep) runs on any exit,
# and every object outside the run is diffed against a before-snapshot.
#
# The API key is read from E2E_UDM_KEY_FILE, mounted read-only into the
# bouncer and piped to curl on stdin. It is never printed or copied.
# shellcheck shell=bash
set -u
cd "$(dirname "$0")" || exit 1
. ./lib.sh

[ "${E2E_UDM_CONFIRM:-}" = yes ] || { echo "refusing: set E2E_UDM_CONFIRM=yes to run against the real controller" >&2; exit 2; }

# Per-machine settings (controller URL, key file) live in the gitignored udm.env.
# shellcheck source=/dev/null
[ -f ./udm.env ] && . ./udm.env
UDM_URL=${E2E_UDM_URL:-}
UDM_SITE=${E2E_UDM_SITE:-default}
PAIR=${E2E_UDM_PAIR:-Test A->Test B}
SRC_ZONE=${PAIR%%->*}; DST_ZONE=${PAIR##*->}
KEY_FILE=${E2E_UDM_KEY_FILE:-}
[ -n "$UDM_URL" ] || { echo "E2E_UDM_URL is not set (put it in e2e.local/udm.env)" >&2; exit 2; }
[ -s "$KEY_FILE" ] || { echo "key file missing or empty: E2E_UDM_KEY_FILE" >&2; exit 2; }

RUN=e2e-$(date +%s | tail -c 7)
DESC="$RUN zone e2e, managed by cs-unifi-bouncer-pro"
UDM=csue2e-udm
VOL=csue2e-udm-data-$RUN
CAP=5
OUT=${E2E_UDM_OUT:-udm-$RUN}
POL_V4="$RUN-policy-$SRC_ZONE-$DST_ZONE-v4"
POL_V6="$RUN-policy-$SRC_ZONE-$DST_ZONE-v6"
mkdir -p "$OUT"
DCC="docker compose"

# --- controller access -------------------------------------------------------
# ureq <METHOD> <integration path> [json body]: the key reaches curl as a header on stdin.
ureq() {
  local m=$1 p=$2 body=${3:-}
  local args=(-sk --max-time 30 -X "$m" -H @- -H 'Accept: application/json')
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data "$body")
  tr -d '\r\n' < "$KEY_FILE" | sed 's/^/X-API-KEY: /' | curl "${args[@]}" "$UDM_URL/proxy/network/integration/v1$p"
}
SITE_ID=
# paged <collection>: every item across pages, as {"data":[...]}
paged() {
  local off=0 total=1 acc='[]' page
  while [ "$off" -lt "$total" ]; do
    page=$(ureq GET "/sites/$SITE_ID/$1?limit=200&offset=$off") || return 1
    total=$(echo "$page" | q 'd.totalCount') || return 1
    acc=$(printf '%s\n%s' "$acc" "$page" | node -e 'let r="";process.stdin.on("data",c=>r+=c).on("end",()=>{const i=r.indexOf("\n");process.stdout.write(JSON.stringify(JSON.parse(r.slice(0,i)).concat(JSON.parse(r.slice(i+1)).data)))})')
    off=$((off+200))
  done
  echo "{\"data\":$acc}"
}
tmls()     { paged traffic-matching-lists; }
policies() { paged firewall/policies; }
zones()    { ureq GET "/sites/$SITE_ID/firewall/zones?limit=200"; }
mine_tmls()     { tmls | q "data.filter(x => x.name.startsWith('$RUN-'))"; }
mine_policies() { policies | q "data.filter(x => x.name.startsWith('$RUN-'))"; }
mine_count() { echo $(( $(mine_tmls | wc -l) + $(mine_policies | wc -l) )); }
tml_ips()   { tmls | q "(data.find(x => x.name === '$1') || {items: []}).items.map(i => i.value)"; }
tml_has()   { tml_ips "$1" | grep -qx "$2"; }
tml_lacks() { ! tml_has "$1" "$2"; }
shard_count()  { tmls | q "data.filter(x => x.name.startsWith('$RUN-block-$1-')).length"; }
policy_exists() { [ "$(policies | q "data.filter(x => x.name === '$1').length")" = 1 ]; }

# own_delete <tml|policy> <id>: re-reads the object and deletes it only if its name carries $RUN.
own_delete() {
  local coll name
  [ "$1" = tml ] && coll=traffic-matching-lists || coll=firewall/policies
  name=$(ureq GET "/sites/$SITE_ID/$coll/$2" | q 'd.name')
  case "$name" in
    "$RUN-"*) ureq DELETE "/sites/$SITE_ID/$coll/$2" >/dev/null ;;
    *) echo "  refusing to delete $1 $2 ($name): not created by this run" >&2; return 1 ;;
  esac
}

snapshot() { tmls > "$OUT/tml-$1.json"; policies > "$OUT/pol-$1.json"; zones > "$OUT/zones-$1.json"; }
# foreign_diff <a> <b>: every object outside this run added, removed or changed between two snapshots
foreign_diff() {
  node -e '
    const f=require("fs"),[o,a,b,run]=process.argv.slice(1);
    const load=(k,l)=>JSON.parse(f.readFileSync(`${o}/${k}-${l}.json`,"utf8")).data.filter(x=>!x.name.startsWith(run+"-"));
    const out=[];
    for(const k of ["tml","pol","zones"]){
      const A=new Map(load(k,a).map(x=>[x.id,JSON.stringify(x)])),B=new Map(load(k,b).map(x=>[x.id,JSON.stringify(x)]));
      for(const [id,v] of A){ if(!B.has(id)) out.push(`${k} removed ${id}`); else if(B.get(id)!==v) out.push(`${k} changed ${id}`); }
      for(const id of B.keys()) if(!A.has(id)) out.push(`${k} added ${id}`);
    }
    process.stdout.write(out.join("\n"));
  ' "$OUT" "$1" "$2" "$RUN"
}

# --- bouncer ----------------------------------------------------------------
BENV=(
  -e FIREWALL_MODE=zone -e "UNIFI_URL=$UDM_URL" -e UNIFI_VERIFY_TLS=false
  -e UNIFI_API_KEY_FILE=/run/secrets/unifi_api_key -e "UNIFI_SITES=$UDM_SITE" -e UNIFI_SITES_AUTO=false
  -e "ZONE_PAIRS=$PAIR" -e CLOUDFLARE_WHITELIST_ENABLED=false
  -e "GROUP_NAME_TEMPLATE=$RUN-block-{{.Family}}-{{.Index}}"
  -e "POLICY_NAME_TEMPLATE=$RUN-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}"
  -e "OBJECT_DESCRIPTION=$DESC"
  -e "FIREWALL_GROUP_CAPACITY_V4=$CAP" -e "FIREWALL_GROUP_CAPACITY_V6=$CAP"
  -e CROWDSEC_LAPI_URL=http://crowdsec:8080 -e "CROWDSEC_LAPI_KEY=$LAPI_KEY" -e CROWDSEC_LAPI_ALLOW_HTTP=true
  -e HTTPS_PROXY= -e HTTP_PROXY= -e LOG_LEVEL=debug
  -v "$KEY_FILE:/run/secrets/unifi_api_key:ro" -v "$VOL:/data"
)
bouncer_up() { # bouncer_up [extra docker args...]
  docker rm -f "$UDM" >/dev/null 2>&1
  docker run -d --name "$UDM" --network csue2e_e2e \
    -p 127.0.0.1:18081:8081 -p 127.0.0.1:19090:9090 \
    --read-only --tmpfs /tmp:size=10m,noexec,nosuid --cap-drop ALL \
    --security-opt no-new-privileges:true --security-opt "seccomp=../security/seccomp-unifi.json" \
    "${BENV[@]}" -e CROWDSEC_POLL_INTERVAL=2s -e SYNC_INTERVAL=5s -e FIREWALL_RECONCILE_INTERVAL=30s \
    "$@" cs-unifi-bouncer-pro:e2e >/dev/null
}
ulogs() { docker logs "$UDM" 2>&1; }
uoff()  { docker run --rm --network csue2e_e2e "${BENV[@]}" cs-unifi-bouncer-pro:e2e "$@"; }
decide()   { $DCC exec -T crowdsec cscli decisions add -i "$1" -d "${2:-1h}" -R "udm e2e" >/dev/null; }
undecide() { $DCC exec -T crowdsec cscli decisions delete -i "$1" >/dev/null; }

cleanup() {
  trap - EXIT INT TERM
  step "cleanup (only $RUN-* objects)"
  ulogs > "$OUT/bouncer.log" 2>/dev/null
  docker rm -f "$UDM" >/dev/null 2>&1
  if [ -n "$SITE_ID" ]; then
    uoff drain --force > "$OUT/drain-cleanup.log" 2>&1
    local id
    for id in $(policies | q "data.filter(x => x.name.startsWith('$RUN-')).map(x => x.id)"); do own_delete policy "$id" && echo "  swept leftover policy $id"; done
    for id in $(tmls | q "data.filter(x => x.name.startsWith('$RUN-')).map(x => x.id)"); do own_delete tml "$id" && echo "  swept leftover TML $id"; done
    [ "$(mine_count)" = 0 ] && ok "no $RUN-* object left on the controller" || bad "$(mine_count) $RUN-* objects left on the controller"
    snapshot after
    diff=$(foreign_diff before after)
    [ -z "$diff" ] && ok "no object outside this run was added, removed or changed" || { bad "objects outside this run changed:"; echo "$diff" | sed 's/^/    /'; }
  fi
  docker volume rm "$VOL" >/dev/null 2>&1
  $DCC stop crowdsec >/dev/null 2>&1
  echo; echo "udm e2e $RUN: $PASS passed, $FAIL failed, $SKIP skipped (artifacts in e2e.local/$OUT)"
  [ "$FAIL" = 0 ]
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# --- 0. read-only preflight ------------------------------------------------
step "0. preflight (read-only)"
SITE_ID=$(ureq GET /sites | q "(data.find(s => s.internalReference === '$UDM_SITE') || {}).id")
[ -n "$SITE_ID" ] && ok "API key reads site $UDM_SITE" || { bad "site $UDM_SITE not visible with this key"; exit 1; }
for z in "$SRC_ZONE" "$DST_ZONE"; do
  n=$(zones | q "((data.find(x => x.name === '$z') || {}).networkIds || ['missing']).length")
  nets=$(zones | q "(data.find(x => x.name === '$z') || {}).networkIds")
  case "$nets" in
    '') bad "zone $z not found"; exit 1 ;;
    '[]') bad "zone $z has no networks; the bouncer refuses empty zones"; exit 1 ;;
    *) ok "zone $z exists with $n network(s)" ;;
  esac
done
snapshot before
[ "$(mine_count)" = 0 ] && ok "prefix $RUN unused before the run" || { bad "prefix $RUN already in use"; exit 1; }

$DCC up -d crowdsec >/dev/null 2>&1
wait_for 120 "CrowdSec LAPI healthy" sh -c "docker compose ps crowdsec --format '{{.Health}}' | grep -qx healthy" || exit 1
$DCC exec -T crowdsec cscli decisions delete --all >/dev/null 2>&1

# --- 1. dry run writes nothing -----------------------------------------------
step "1. DRY_RUN=true writes nothing"
decide 192.0.2.10
bouncer_up -e DRY_RUN=true -e FIREWALL_MODE=auto
wait_for 90 "dry-run bouncer ready" ready || exit 1
sleep 15
# The resolved mode is only logged on the dry-run path, so auto-detection is checked here.
check "FIREWALL_MODE=auto resolves to zone on this console" sh -c "docker logs $UDM 2>&1 | grep -q '\"mode\":\"zone\"'"
snapshot dry
[ -z "$(foreign_diff before dry)" ] && [ "$(mine_count)" = 0 ] && ok "no controller change during dry run" || { bad "dry run changed the controller"; exit 1; }
ulogs > "$OUT/dry.log"

# --- 2. provisioning ---------------------------------------------------------
step "2. zone-mode provisioning for $PAIR"
bouncer_up
wait_for 90 "bouncer ready" ready || exit 1
wait_for 60 "ban 192.0.2.10 lands in $RUN-block-v4-0" tml_has "$RUN-block-v4-0" 192.0.2.10
pol=$(policies | q "data.find(x => x.name === '$POL_V4-0')")
[ -n "$pol" ] && ok "policy $POL_V4-0 exists" || bad "v4 policy missing"
tml_id=$(tmls | q "data.find(x => x.name === '$RUN-block-v4-0').id")
src_id=$(zones | q "data.find(x => x.name === '$SRC_ZONE').id"); dst_id=$(zones | q "data.find(x => x.name === '$DST_ZONE').id")
pcheck() { echo "$pol" | q "$1" | grep -qx true; }
check "policy is an enabled BLOCK with the run description" pcheck "d.action.type === 'BLOCK' && d.enabled && d.description === '$DESC'"
check "policy runs $SRC_ZONE -> $DST_ZONE" pcheck "d.source.zoneId === '$src_id' && d.destination.zoneId === '$dst_id'"
check "policy matches sources in the v4 shard list" pcheck "d.source.trafficFilter.ipAddressFilter.trafficMatchingListId === '$tml_id'"

# --- 3. ban / unban ----------------------------------------------------------
step "3. ban and unban, IPv4 and IPv6"
decide 198.51.100.10; decide 2001:db8::10
wait_for 60 "v4 ban 198.51.100.10 synced" tml_has "$RUN-block-v4-0" 198.51.100.10
wait_for 60 "v6 ban 2001:db8::10 synced" tml_has "$RUN-block-v6-0" 2001:db8::10
check "v6 policy exists" policy_exists "$POL_V6-0"
undecide 198.51.100.10
wait_for 60 "unban 198.51.100.10 removed" tml_lacks "$RUN-block-v4-0" 198.51.100.10
check "other v4 ban kept" tml_has "$RUN-block-v4-0" 192.0.2.10

# --- 4. sharding ---------------------------------------------------------------
step "4. sharding at capacity $CAP"
SHARD_IPS="21 22 23 24 25 26 27"
for i in $SHARD_IPS; do decide "203.0.113.$i"; done
two_shards() { [ "$(shard_count v4)" -ge 2 ]; }
wait_for 90 "second v4 shard created" two_shards
wait_for 60 "second shard has its own policy" policy_exists "$POL_V4-1"
all_there() { local ips i; ips=$(tmls | q "data.filter(x => x.name.startsWith('$RUN-block-v4-')).flatMap(x => x.items.map(i => i.value))"); for i in $SHARD_IPS; do echo "$ips" | grep -qx "203.0.113.$i" || return 1; done; }
wait_for 60 "all 7 sharded IPs present across shards" all_there
for i in $SHARD_IPS; do undecide "203.0.113.$i"; done
one_shard() { [ "$(shard_count v4)" = 1 ]; }
wait_for 150 "empty trailing shard pruned" one_shard
policy_gone() { ! policy_exists "$1"; }
check "pruned shard's policy removed" policy_gone "$POL_V4-1"

# --- 5. drift repair -----------------------------------------------------------
step "5. drift repair on this run's own list"
tml_id=$(tmls | q "data.find(x => x.name === '$RUN-block-v4-0').id")
name=$(ureq GET "/sites/$SITE_ID/traffic-matching-lists/$tml_id" | q 'd.name')
if [ "$name" = "$RUN-block-v4-0" ]; then
  ureq PUT "/sites/$SITE_ID/traffic-matching-lists/$tml_id" \
    "{\"type\":\"IPV4_ADDRESSES\",\"name\":\"$name\",\"items\":[{\"type\":\"IP_ADDRESS\",\"value\":\"192.0.2.1\"}]}" >/dev/null
  check "list emptied out of band" tml_lacks "$RUN-block-v4-0" 192.0.2.10
  wait_for 90 "reconcile restored 192.0.2.10" tml_has "$RUN-block-v4-0" 192.0.2.10
else
  skip "drift: shard list name mismatch ($name)"
fi

# --- 6. SIGHUP and restart -----------------------------------------------------
step "6. SIGHUP reload and restart"
docker kill -s HUP "$UDM" >/dev/null
wait_for 60 "SIGHUP reloaded zone pairs and policies" sh -c "docker logs $UDM 2>&1 | grep -q 'SIGHUP: zone pairs and policies reloaded successfully'"
check "still ready after SIGHUP" ready
n_before=$(mine_count)
docker restart "$UDM" >/dev/null
wait_for 90 "ready after restart" ready
sleep 15
n_after=$(mine_count)
[ "$n_before" = "$n_after" ] && ok "restart adopted existing objects ($n_after), no duplicates" || bad "object count $n_before -> $n_after across restart"
check "ban survived restart" tml_has "$RUN-block-v4-0" 192.0.2.10
ulogs > "$OUT/bouncer-run.log"
errs=$(grep -c '"level":"error"' "$OUT/bouncer-run.log")
[ "$errs" = 0 ] && ok "no error-level log lines" || bad "$errs error-level log lines (see $OUT/bouncer-run.log)"

# --- 7. drain ------------------------------------------------------------------
step "7. drain removes everything this run made"
docker stop "$UDM" >/dev/null
out=$(uoff drain --force 2>&1); rc=$?
echo "$out" > "$OUT/drain.log"
[ $rc = 0 ] && ok "drain exits 0" || bad "drain rc=$rc: $(echo "$out" | tail -3)"
[ "$(mine_count)" = 0 ] && ok "drain removed every $RUN-* list and policy" || bad "$(mine_count) $RUN-* objects left after drain"
