# Helpers for udm.sh: controller access, ownership rules, snapshots and the
# bouncer containers. Source after lib.sh with UDM_URL, SITE_ID, KEY_FILE,
# RUN, OUT and the zone names set.
# shellcheck shell=bash

# Objects with these fixed names are created by the Cloudflare whitelist, by
# filtered zone pairs and by filter changes. A run owns them only because the
# preflight proved none existed before it started.
FIXED_RE='^crowdsec-(whitelist-cloudflare-|ports-src-|ports-dst-|dstips-v4-|dstips-v6-|policy-stage-)'
OURS="(x => x.name.startsWith('$RUN-') || /$FIXED_RE/.test(x.name))"
FIXED="(x => /$FIXED_RE/.test(x.name))"

# ureq <METHOD> <integration path> [json body]: the key reaches curl as a header on stdin.
ureq() {
  local m=$1 p=$2 body=${3:-}
  local args=(-sk --max-time 30 -X "$m" -H @- -H 'Accept: application/json')
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data "$body")
  tr -d '\r\n' < "$KEY_FILE" | sed 's/^/X-API-KEY: /' | curl "${args[@]}" "$UDM_URL/proxy/network/integration/v1$p"
}
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
zone_id()  { zones | q "data.find(x => x.name === '$1').id"; }
ours_count()  { echo $(( $(tmls | q "data.filter($OURS).length") + $(policies | q "data.filter($OURS).length") )); }
fixed_count() { echo $(( $(tmls | q "data.filter($FIXED).length") + $(policies | q "data.filter($FIXED).length") )); }
prefix_count() { echo $(( $(tmls | q "data.filter(x => x.name.startsWith('$1-')).length") + $(policies | q "data.filter(x => x.name.startsWith('$1-')).length") )); }
tml_ips()   { tmls | q "(data.find(x => x.name === '$1') || {items: []}).items.map(i => i.value)"; }
tml_has()   { tml_ips "$1" | grep -qx "$2"; }
tml_lacks() { ! tml_has "$1" "$2"; }
# family_ips <prefix> <v4|v6>: every address across that prefix's shard lists
family_ips() { tmls | q "data.filter(x => x.name.startsWith('$1-block-$2-')).flatMap(x => x.items.map(i => String(i.value)))"; }
family_has() { family_ips "$1" "$2" | grep -qx "$3"; }
family_lacks() { ! family_has "$1" "$2" "$3"; }
shard_count() { tmls | q "data.filter(x => x.name.startsWith('$1-block-$2-')).length"; }
policy_exists() { [ "$(policies | q "data.filter(x => x.name === '$1').length")" = 1 ]; }
policy_gone() { ! policy_exists "$1"; }

# own_delete <tml|policy> <id>: re-reads the object and deletes it only if this run owns its name.
own_delete() {
  local coll name owned
  [ "$1" = tml ] && coll=traffic-matching-lists || coll=firewall/policies
  name=$(ureq GET "/sites/$SITE_ID/$coll/$2" | q 'd.name')
  owned=$(printf '{"name":%s}' "$(node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$name")" | q "$OURS(d)")
  if [ "$owned" = true ] && [ -n "$name" ]; then
    ureq DELETE "/sites/$SITE_ID/$coll/$2" >/dev/null
  else
    echo "  refusing to delete $1 $2 ($name): not created by this run" >&2; return 1
  fi
}
sweep_ours() {
  local id
  for id in $(policies | q "data.filter($OURS).map(x => x.id)"); do own_delete policy "$id" && echo "  swept leftover policy $id"; done
  for id in $(tmls | q "data.filter($OURS).map(x => x.id)"); do own_delete tml "$id" && echo "  swept leftover list $id"; done
}

snapshot() { tmls > "$OUT/tml-$1.json"; policies > "$OUT/pol-$1.json"; zones > "$OUT/zones-$1.json"; }
# foreign_diff <a> <b>: every object this run does not own that was added, removed or changed.
# Lines carry the object name: another bouncer on the same site (e.g. a production
# crowdsec-block-*/crowdsec-policy-* set) can change its own objects during a run.
foreign_diff() {
  node -e '
    const f=require("fs"),[o,a,b,run,fixed]=process.argv.slice(1),re=new RegExp(fixed);
    const mine=x=>x.name.startsWith(run+"-")||re.test(x.name);
    const load=(k,l)=>JSON.parse(f.readFileSync(`${o}/${k}-${l}.json`,"utf8")).data.filter(x=>!mine(x));
    const out=[];
    for(const k of ["tml","pol","zones"]){
      const A=new Map(load(k,a).map(x=>[x.id,x])),B=new Map(load(k,b).map(x=>[x.id,x]));
      const line=(what,x)=>out.push(`${k} ${what} ${x.id} ${x.name}`);
      for(const [id,x] of A){ if(!B.has(id)) line("removed",x); else if(JSON.stringify(B.get(id))!==JSON.stringify(x)) line("changed",x); }
      for(const [id,x] of B) if(!A.has(id)) line("added",x);
    }
    process.stdout.write(out.join("\n"));
  ' "$OUT" "$1" "$2" "$RUN" "$FIXED_RE"
}

# --- bouncer containers ---------------------------------------------------------
# benv <prefix>: container settings for one section; each prefix has its own volume.
benv() {
  BENV=(
    -e FIREWALL_MODE=zone -e "UNIFI_URL=$UDM_URL" -e UNIFI_VERIFY_TLS=false
    -e UNIFI_API_KEY_FILE=/run/secrets/unifi_api_key -e "UNIFI_SITES=$UDM_SITE" -e UNIFI_SITES_AUTO=false
    -e "ZONE_PAIRS=$PAIR" -e CLOUDFLARE_WHITELIST_ENABLED=false
    -e "GROUP_NAME_TEMPLATE=$1-block-{{.Family}}-{{.Index}}"
    -e "POLICY_NAME_TEMPLATE=$1-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}"
    -e "OBJECT_DESCRIPTION=$1 zone e2e, managed by cs-unifi-bouncer-pro"
    -e "FIREWALL_GROUP_CAPACITY_V4=$CAP" -e "FIREWALL_GROUP_CAPACITY_V6=$CAP"
    -e CROWDSEC_LAPI_URL=http://crowdsec:8080 -e "CROWDSEC_LAPI_KEY=$LAPI_KEY" -e CROWDSEC_LAPI_ALLOW_HTTP=true
    -e HTTPS_PROXY= -e HTTP_PROXY= -e LOG_LEVEL=debug
    -v "$KEY_FILE:/run/secrets/unifi_api_key:ro" -v "csue2e-udm-$1:/data"
  )
}
# bouncer_up <prefix> [--image <image>] [extra docker args...]
bouncer_up() {
  local prefix=$1 image=cs-unifi-bouncer-pro:e2e; shift
  [ "${1:-}" = --image ] && { image=$2; shift 2; }
  benv "$prefix"
  docker rm -f "$UDM" >/dev/null 2>&1
  docker run -d --name "$UDM" --network csue2e_e2e \
    -p 127.0.0.1:18081:8081 -p 127.0.0.1:19090:9090 \
    --read-only --tmpfs /tmp:size=10m,noexec,nosuid --cap-drop ALL \
    --security-opt no-new-privileges:true --security-opt "seccomp=../security/seccomp-unifi.json" \
    "${BENV[@]}" -e CROWDSEC_POLL_INTERVAL=2s -e SYNC_INTERVAL=5s -e FIREWALL_RECONCILE_INTERVAL=30s \
    "$@" "$image" >/dev/null
  STARTED="$STARTED $prefix"
}
ulogs() { docker logs "$UDM" 2>&1; }
ulog_count() { ulogs | grep -c -- "$1"; }
# drain_prefix <prefix>: this checkout's drain against that section's database
drain_prefix() { benv "$1"; docker run --rm --network csue2e_e2e "${BENV[@]}" cs-unifi-bouncer-pro:e2e drain --force; }
decide()   { docker compose exec -T crowdsec cscli decisions add -i "$1" -d "${2:-1h}" -R "udm e2e" >/dev/null; }
undecide() { docker compose exec -T crowdsec cscli decisions delete -i "$1" >/dev/null; }
clear_decisions() { docker compose exec -T crowdsec cscli decisions delete --all >/dev/null 2>&1; }
