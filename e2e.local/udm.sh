#!/usr/bin/env bash
# Opt-in zone-mode e2e against a real UniFi OS console (UDM).
#
#   E2E_UDM_CONFIRM=yes bash e2e.local/udm.sh
#
# Sections (E2E_UDM_SECTIONS, default "main filters upgrade"):
#   main     provisioning, v4/v6 ban and unban, sharding, drift repair,
#            SIGHUP, restart adoption, drain
#   filters  a zone pair with destination ports and IPs plus the Cloudflare
#            whitelist, then both removed again
#   upgrade  the published E2E_UDM_FROM image (default 1.2.5) builds a ban
#            database and objects; this checkout takes over the same database
#
# Scope: one zone pair (E2E_UDM_PAIR, default "Test A->Test B") on one site.
# Objects are named with a per-run prefix (e2e-<id>-<section>-) and tagged
# with a per-run description. The filters section also creates lists and
# policies with fixed names (crowdsec-ports-*, crowdsec-dstips-*,
# crowdsec-whitelist-cloudflare-*); the run refuses to start if any such
# object already exists. The script edits or deletes an object only after
# re-reading its name and confirming this run owns it. Cleanup (drain, then a
# sweep of owned names) runs on any exit, and every other list, policy and
# zone is diffed against a before-snapshot.
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
SECTIONS=${E2E_UDM_SECTIONS:-main filters upgrade}
FROM=${E2E_UDM_FROM:-1.2.5}
[ -n "$UDM_URL" ] || { echo "E2E_UDM_URL is not set (put it in e2e.local/udm.env)" >&2; exit 2; }
[ -s "$KEY_FILE" ] || { echo "key file missing or empty: E2E_UDM_KEY_FILE" >&2; exit 2; }

RUN=e2e-$(date +%s | tail -c 7)
UDM=csue2e-udm
CAP=5
OUT=${E2E_UDM_OUT:-udm-$RUN}
SITE_ID=
STARTED=
mkdir -p "$OUT"
. ./udm-lib.sh

cleanup() {
  trap - EXIT INT TERM
  step "cleanup (only objects this run owns)"
  ulogs > "$OUT/last-bouncer.log" 2>/dev/null
  docker rm -f "$UDM" >/dev/null 2>&1
  local p
  if [ -n "$SITE_ID" ]; then
    for p in $(echo "$STARTED" | tr ' ' '\n' | sort -u); do drain_prefix "$p" > "$OUT/drain-cleanup-$p.log" 2>&1; done
    sweep_ours
    [ "$(ours_count)" = 0 ] && ok "no object this run created is left on the controller" || bad "$(ours_count) objects this run created are left on the controller"
    snapshot after
    diff=$(foreign_diff before after)
    [ -z "$diff" ] && ok "no object outside this run was added, removed or changed" || { bad "objects outside this run changed:"; echo "$diff" | sed 's/^/    /'; }
  fi
  for p in $(echo "$STARTED" | tr ' ' '\n' | sort -u); do docker volume rm "csue2e-udm-$p" >/dev/null 2>&1; done
  docker compose stop crowdsec >/dev/null 2>&1
  echo; echo "udm e2e $RUN ($SECTIONS): $PASS passed, $FAIL failed, $SKIP skipped (artifacts in e2e.local/$OUT)"
  [ "$FAIL" = 0 ]
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# section_end <prefix>: stop the bouncer, drain, and require every object of the prefix gone
section_end() {
  ulogs > "$OUT/$1.log"
  docker stop "$UDM" >/dev/null
  local out rc
  out=$(drain_prefix "$1" 2>&1); rc=$?
  echo "$out" > "$OUT/drain-$1.log"
  [ $rc = 0 ] && ok "drain exits 0" || bad "drain rc=$rc: $(echo "$out" | tail -3)"
  [ "$(prefix_count "$1")" = 0 ] && ok "drain removed every $1-* list and policy" || bad "$(prefix_count "$1") $1-* objects left after drain"
}
no_errors() { check "no error-level log lines" sh -c "! docker logs $UDM 2>&1 | grep -q '\"level\":\"error\"'"; }

# --- main -------------------------------------------------------------------------
section_main() {
  local P=$RUN-m pol pv4="$RUN-m-policy-$SRC_ZONE-$DST_ZONE-v4" pv6="$RUN-m-policy-$SRC_ZONE-$DST_ZONE-v6" tml_id i
  step "main 1. DRY_RUN=true writes nothing"
  clear_decisions
  decide 192.0.2.10
  bouncer_up "$P" -e DRY_RUN=true -e FIREWALL_MODE=auto
  wait_for 90 "dry-run bouncer ready" ready || return 1
  sleep 15
  # The resolved mode is only logged on the dry-run path, so auto-detection is checked here.
  check "FIREWALL_MODE=auto resolves to zone on this console" sh -c "docker logs $UDM 2>&1 | grep -q '\"mode\":\"zone\"'"
  snapshot dry
  [ -z "$(foreign_diff before dry)" ] && [ "$(ours_count)" = 0 ] && ok "no controller change during dry run" || { bad "dry run changed the controller"; return 1; }

  step "main 2. provisioning for $PAIR"
  bouncer_up "$P"
  wait_for 90 "bouncer ready" ready || return 1
  wait_for 60 "ban 192.0.2.10 lands in $P-block-v4-0" tml_has "$P-block-v4-0" 192.0.2.10
  pol=$(policies | q "data.find(x => x.name === '$pv4-0')")
  [ -n "$pol" ] && ok "policy $pv4-0 exists" || bad "v4 policy missing"
  tml_id=$(tmls | q "data.find(x => x.name === '$P-block-v4-0').id")
  pcheck() { echo "$pol" | q "$1" | grep -qx true; }
  check "policy is an enabled BLOCK with the run description" pcheck "d.action.type === 'BLOCK' && d.enabled && d.description === '$P zone e2e, managed by cs-unifi-bouncer-pro'"
  check "policy runs $SRC_ZONE -> $DST_ZONE" pcheck "d.source.zoneId === '$(zone_id "$SRC_ZONE")' && d.destination.zoneId === '$(zone_id "$DST_ZONE")'"
  check "policy matches sources in the v4 shard list" pcheck "d.source.trafficFilter.ipAddressFilter.trafficMatchingListId === '$tml_id'"

  step "main 3. ban and unban, IPv4 and IPv6"
  decide 198.51.100.10; decide 2001:db8::10
  wait_for 60 "v4 ban 198.51.100.10 synced" tml_has "$P-block-v4-0" 198.51.100.10
  wait_for 60 "v6 ban 2001:db8::10 synced" tml_has "$P-block-v6-0" 2001:db8::10
  check "v6 policy exists" policy_exists "$pv6-0"
  undecide 198.51.100.10
  wait_for 60 "unban 198.51.100.10 removed" tml_lacks "$P-block-v4-0" 198.51.100.10
  check "other v4 ban kept" tml_has "$P-block-v4-0" 192.0.2.10

  step "main 4. sharding at capacity $CAP"
  for i in 21 22 23 24 25 26 27; do decide "203.0.113.$i"; done
  two_shards() { [ "$(shard_count "$P" v4)" -ge 2 ]; }
  wait_for 90 "second v4 shard created" two_shards
  wait_for 60 "second shard has its own policy" policy_exists "$pv4-1"
  all_there() { local ips j; ips=$(family_ips "$P" v4); for j in 21 22 23 24 25 26 27; do echo "$ips" | grep -qx "203.0.113.$j" || return 1; done; }
  wait_for 60 "all 7 sharded IPs present across shards" all_there
  for i in 21 22 23 24 25 26 27; do undecide "203.0.113.$i"; done
  one_shard() { [ "$(shard_count "$P" v4)" = 1 ]; }
  wait_for 150 "empty trailing shard pruned" one_shard
  check "pruned shard's policy removed" policy_gone "$pv4-1"

  step "main 5. drift repair on this run's own list"
  tml_id=$(tmls | q "data.find(x => x.name === '$P-block-v4-0').id")
  if [ "$(ureq GET "/sites/$SITE_ID/traffic-matching-lists/$tml_id" | q 'd.name')" = "$P-block-v4-0" ]; then
    ureq PUT "/sites/$SITE_ID/traffic-matching-lists/$tml_id" \
      "{\"type\":\"IPV4_ADDRESSES\",\"name\":\"$P-block-v4-0\",\"items\":[{\"type\":\"IP_ADDRESS\",\"value\":\"192.0.2.1\"}]}" >/dev/null
    check "list emptied out of band" tml_lacks "$P-block-v4-0" 192.0.2.10
    wait_for 90 "reconcile restored 192.0.2.10" tml_has "$P-block-v4-0" 192.0.2.10
  else
    skip "drift: shard list name mismatch"
  fi

  step "main 6. SIGHUP reload and restart"
  docker kill -s HUP "$UDM" >/dev/null
  wait_for 60 "SIGHUP reloaded zone pairs and policies" sh -c "docker logs $UDM 2>&1 | grep -q 'SIGHUP: zone pairs and policies reloaded successfully'"
  check "still ready after SIGHUP" ready
  local n_before n_after
  n_before=$(prefix_count "$P")
  docker restart "$UDM" >/dev/null
  wait_for 90 "ready after restart" ready
  sleep 15
  n_after=$(prefix_count "$P")
  [ "$n_before" = "$n_after" ] && ok "restart adopted existing objects ($n_after), no duplicates" || bad "object count $n_before -> $n_after across restart"
  check "ban survived restart" tml_has "$P-block-v4-0" 192.0.2.10
  no_errors

  step "main 7. drain"
  section_end "$P"
}

# --- filters and Cloudflare ------------------------------------------------------
section_filters() {
  local P=$RUN-f pv4="$RUN-f-policy-$SRC_ZONE-$DST_ZONE-v4-0" pol ports_id ips_id
  local fpair="$SRC_ZONE->$DST_ZONE:443,8443@192.168.4.10"
  step "filters 1. destination ports and IPs, Cloudflare whitelist"
  clear_decisions
  decide 192.0.2.30
  bouncer_up "$P" -e "ZONE_PAIRS=$fpair" -e CLOUDFLARE_WHITELIST_ENABLED=true -e "CLOUDFLARE_ZONE_PAIRS=$PAIR"
  wait_for 120 "bouncer ready" ready || return 1
  wait_for 60 "ban 192.0.2.30 lands" tml_has "$P-block-v4-0" 192.0.2.30
  ports_id=$(tmls | q "(data.find(x => x.name.startsWith('crowdsec-ports-dst-$SRC_ZONE-$DST_ZONE')) || {}).id")
  ips_id=$(tmls | q "(data.find(x => x.name.startsWith('crowdsec-dstips-v4-$SRC_ZONE-$DST_ZONE')) || {}).id")
  [ -n "$ports_id" ] && ok "destination port list created" || bad "destination port list missing"
  [ -n "$ips_id" ] && ok "destination IP list created" || bad "destination IP list missing"
  list_values() { tmls | q "(data.find(x => x.id === '$1') || {items: []}).items.map(i => String(i.value)).sort().join(',')"; }
  [ "$(list_values "$ports_id")" = "443,8443" ] && ok "port list holds 443 and 8443" || bad "port list holds: $(list_values "$ports_id")"
  [ "$(list_values "$ips_id")" = "192.168.4.10" ] && ok "IP list holds 192.168.4.10" || bad "IP list holds: $(list_values "$ips_id")"
  pol=$(policies | q "data.find(x => x.name === '$pv4')")
  pcheck() { echo "$pol" | q "$1" | grep -qx true; }
  check "block policy filters on the destination ports" pcheck "d.destination.trafficFilter.portFilter.trafficMatchingListId === '$ports_id'"
  check "block policy filters on the destination IPs" pcheck "d.destination.trafficFilter.ipAddressFilter.trafficMatchingListId === '$ips_id'"
  cf_list() { [ "$(tmls | q "(data.find(x => x.name === 'crowdsec-whitelist-cloudflare-v4') || {items: []}).items.length")" -gt 5 ]; }
  wait_for 90 "Cloudflare v4 list filled" cf_list
  cf_pol() { policies | q "data.some(x => x.name.startsWith('crowdsec-whitelist-cloudflare-') && x.action.type === 'ALLOW' && x.source.zoneId === '$(zone_id "$SRC_ZONE")' && x.destination.zoneId === '$(zone_id "$DST_ZONE")')" | grep -qx true; }
  wait_for 60 "Cloudflare ALLOW policy on $PAIR" cf_pol
  check "Cloudflare allow precedes the block" sh -c "! docker logs $UDM 2>&1 | grep -q 'follows block'"
  ulogs | grep -q 'cannot verify Cloudflare allow precedes block' && skip "controller did not report policy order; precedence unverified"
  no_errors

  step "filters 2. filters and whitelist removed"
  ulogs > "$OUT/$P-filtered.log"
  bouncer_up "$P"
  wait_for 120 "bouncer ready without filters" ready || return 1
  unfiltered() { echo "$(policies | q "data.find(x => x.name === '$pv4')")" | q '!d.destination.trafficFilter' | grep -qx true; }
  wait_for 90 "block policy no longer filters the destination" unfiltered
  check "ban kept through the filter change" tml_has "$P-block-v4-0" 192.0.2.30
  no_fixed() { [ "$(fixed_count)" = 0 ]; }
  wait_for 120 "filter lists and Cloudflare objects removed" no_fixed
  no_errors
  section_end "$P"
}

# --- upgrade from a published release ------------------------------------------------
section_upgrade() {
  local P=$RUN-u old=developingchet/cs-unifi-bouncer-pro:$FROM i
  step "upgrade 1. $FROM builds a ban database"
  docker pull -q "$old" >/dev/null || { bad "cannot pull $old"; return 1; }
  echo "  $(docker run --rm "$old" version 2>&1 | head -1)"
  clear_decisions
  for i in 1 2 3 4 5 6 7; do decide "192.0.2.4$i" 4h; done
  decide 2001:db8::40 4h
  bouncer_up "$P" --image "$old"
  wait_for 120 "$FROM healthy" healthy || { ulogs | tail -5; return 1; }
  old_all() { local j; for j in 1 2 3 4 5 6 7; do family_has "$P" v4 "192.0.2.4$j" || return 1; done; }
  wait_for 120 "$FROM synced 7 v4 bans" old_all
  wait_for 60 "$FROM synced the v6 ban" family_has "$P" v6 2001:db8::40
  [ "$(shard_count "$P" v4)" -ge 2 ] && ok "$FROM made $(shard_count "$P" v4) v4 shards" || bad "$FROM made $(shard_count "$P" v4) v4 shards, expected 2+"
  # A /32 range decision: the old version stores it as a host prefix, which
  # UniFi rejects. Added last so the rest of its state is already on UniFi.
  docker compose exec -T crowdsec cscli decisions add -r 203.0.113.9/32 -d 4h -R "udm e2e" >/dev/null
  sleep 20
  local ids_old ids_new
  owned_ids() { tmls | q "data.filter(x => x.name.startsWith('$P-')).map(x => x.id + ' ' + x.name)"; policies | q "data.filter(x => x.name.startsWith('$P-')).map(x => x.id + ' ' + x.name)"; }
  ids_old=$(owned_ids | sort)
  echo "$ids_old" > "$OUT/$P-ids-old.txt"
  ulogs > "$OUT/$P-old.log"
  docker stop -t 40 "$UDM" >/dev/null

  step "upgrade 2. this checkout on the $FROM database"
  bouncer_up "$P"
  wait_for 120 "ready on the $FROM database" ready || { ulogs | tail -10; return 1; }
  check "host-prefix ban migrated, logged once with a count of 1" sh -c "[ \"\$(docker logs $UDM 2>&1 | grep 'rekeyed bans stored as /32' | grep -c '\"bans\":1')\" = 1 ]"
  wait_for 60 "203.0.113.9 enforced as a bare address" family_has "$P" v4 203.0.113.9
  no_host_prefix() { ! tmls | q "data.filter(x => x.name.startsWith('$P-')).flatMap(x => x.items.map(i => String(i.value)))" | grep -qE '/(32|128)$'; }
  check "no host prefix left in this run's lists" no_host_prefix
  check "all $FROM v4 bans still enforced" old_all
  check "$FROM v6 ban still enforced" family_has "$P" v6 2001:db8::40
  sleep 35 # one reconcile interval
  ids_new=$(owned_ids | sort)
  echo "$ids_new" > "$OUT/$P-ids-new.txt"
  local missing
  missing=$(comm -23 <(echo "$ids_old" | sort) <(echo "$ids_new" | sort))
  [ -z "$missing" ] && ok "every $FROM list and policy kept (same IDs)" || { bad "objects replaced or removed:"; echo "$missing" | sed 's/^/    /'; }
  dups=$(echo "$ids_new" | awk '{ $1=""; print }' | sort | uniq -d)
  [ -z "$dups" ] && ok "no duplicate names" || { bad "duplicate objects:"; echo "$dups" | sed 's/^/    /'; }

  step "upgrade 3. $FROM bans after the upgrade"
  undecide 192.0.2.41
  wait_for 60 "unban of a $FROM ban releases it" family_lacks "$P" v4 192.0.2.41
  decide 192.0.2.50 1h
  wait_for 60 "new ban lands" family_has "$P" v4 192.0.2.50
  docker restart "$UDM" >/dev/null
  wait_for 120 "ready after a second start" ready
  check "migration not repeated" sh -c "[ \"\$(docker logs $UDM 2>&1 | grep -c 'rekeyed bans stored as /32')\" = 1 ]"
  no_errors
  section_end "$P"
}

# --- run ----------------------------------------------------------------------------
step "0. preflight (read-only)"
SITE_ID=$(ureq GET /sites | q "(data.find(s => s.internalReference === '$UDM_SITE') || {}).id")
[ -n "$SITE_ID" ] && ok "API key reads site $UDM_SITE" || { bad "site $UDM_SITE not visible with this key"; SITE_ID=; exit 1; }
for z in "$SRC_ZONE" "$DST_ZONE"; do
  nets=$(zones | q "((data.find(x => x.name === '$z') || {}).networkIds || ['missing'])")
  case "$nets" in
    *missing*) bad "zone $z not found"; SITE_ID=; exit 1 ;;
    '') bad "zone $z has no networks; the bouncer refuses empty zones"; SITE_ID=; exit 1 ;;
    *) ok "zone $z exists with $(echo "$nets" | grep -c .) network(s)" ;;
  esac
done
snapshot before
[ "$(ours_count)" = 0 ] || { bad "objects with this run's prefix or the fixed filter/whitelist names already exist; refusing"; SITE_ID=; exit 1; }
ok "no object with the run prefix or a fixed filter/whitelist name exists"

docker compose up -d crowdsec >/dev/null 2>&1
wait_for 120 "CrowdSec LAPI healthy" sh -c "docker compose ps crowdsec --format '{{.Health}}' | grep -qx healthy" || exit 1
for s in $SECTIONS; do
  case "$s" in
    main|filters|upgrade) "section_$s" || bad "section $s stopped early" ;;
    *) bad "unknown section $s" ;;
  esac
done
