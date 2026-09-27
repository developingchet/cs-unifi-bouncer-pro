#!/usr/bin/env bash
# Upgrade from a released version's ban database to this checkout.
#
#   E2E_FROM=X.Y.Z bash e2e.local/upgrade.sh  (a Docker Hub tag, without "v")
#
# The source release must be able to log in to the self-hosted Network
# Application, which 1.2.5 cannot; upgrades from 1.2.5 are covered by
# udm.sh's upgrade section on a UniFi OS console.
#
# Runs the published image against the local stack until it has written a
# ban database and UniFi objects (two v4 shards, v6, a feed, and a /32 range
# ban the old version stores as a host prefix), stops it, then starts this
# checkout's image on the same /data volume and checks what it inherits.
# shellcheck shell=bash
set -u
cd "$(dirname "$0")" || exit 1
. ./lib.sh
single_run

FROM=${E2E_FROM:?set E2E_FROM to the release to upgrade from, e.g. E2E_FROM=1.3.0}
OLD_IMAGE=developingchet/cs-unifi-bouncer-pro:$FROM
NEW_IMAGE=cs-unifi-bouncer-pro:e2e
UPG=csue2e-upgrade
VOL=csue2e-upgrade-data
OUT=upgrade-$FROM
mkdir -p "$OUT"

upg_run() { # upg_run <image>
  docker rm -f "$UPG" >/dev/null 2>&1
  docker run -d --name "$UPG" --network csue2e_e2e --env-file bouncer.env \
    -p 127.0.0.1:18081:8081 -p 127.0.0.1:19090:9090 \
    -e FIREWALL_MODE=auto -e CROWDSEC_LAPI_URL=http://crowdsec:8080 -e "CROWDSEC_LAPI_KEY=$LAPI_KEY" \
    -e CROWDSEC_POLL_INTERVAL=2s -e UNIFI_URL=https://unifi:8443 -e UNIFI_VERIFY_TLS=false \
    -e UNIFI_SITES=default -e LOG_LEVEL=debug -v "$VOL:/data" "$1" >/dev/null
}
ulogs() { docker logs "$UPG" 2>&1; }
v4_members() { managed_members v4 | sort; }
ids() { # ids: every managed group and rule ID with its name, sorted
  { groups | q "data.filter(g => g.name.startsWith('crowdsec-')).map(g => 'group ' + g._id + ' ' + g.name)"
    rules | q "data.filter(r => r.name.startsWith('crowdsec-')).map(r => 'rule ' + r._id + ' ' + r.name)"; } | sort
}
cleanup() {
  trap - EXIT
  ulogs > "$OUT/bouncer.log" 2>/dev/null
  docker rm -f "$UPG" >/dev/null 2>&1
  docker volume rm "$VOL" >/dev/null 2>&1
  [ -n "${KEEP:-}" ] || $DC down -v --remove-orphans >/dev/null 2>&1
  rm -f .run.pid
  echo; echo "UPGRADE RESULT ($FROM -> checkout): $PASS passed, $FAIL failed, $SKIP skipped"
  [ "$FAIL" = 0 ]
}
trap cleanup EXIT

step "0. stack and images"
docker pull -q "$OLD_IMAGE" >/dev/null || { bad "cannot pull $OLD_IMAGE"; exit 1; }
echo "  old: $(docker run --rm "$OLD_IMAGE" version 2>&1 | head -1)"
stack_up
$DC build bouncer >/dev/null 2>&1 || { bad "build $NEW_IMAGE"; exit 1; }
docker volume rm "$VOL" >/dev/null 2>&1; docker volume create "$VOL" >/dev/null

# --- 1. old version writes its database ---------------------------------------
step "1. $FROM builds a ban database"
upg_run "$OLD_IMAGE"
wait_for 120 "$FROM healthy" healthy || exit 1
OLD_IPS=$(for i in $(seq 1 45); do echo "192.0.2.$i"; done)
for ip in $OLD_IPS; do decide "$ip" 4h; done
decide 2001:db8::1 4h
decide 192.0.2.200 4h   # unbanned after the upgrade
all_old() { local m; m=$(v4_members); for ip in $OLD_IPS; do echo "$m" | grep -qx "$ip" || return 1; done; }
wait_for 120 "$FROM synced 45 v4 bans" all_old
wait_for 60 "$FROM synced the v6 ban" has_ip v6 2001:db8::1
wait_for 60 "$FROM synced the feed" has_ip v4 198.51.100.200
[ "$(group_count v4)" -ge 2 ] && ok "$FROM made $(group_count v4) v4 shards" || bad "$FROM made $(group_count v4) v4 shards, expected 2+"
# A /32 range decision: the old version stores it as 203.0.113.9/32, which
# UniFi rejects. Added last so the rest of its state is already on UniFi.
$DC exec -T crowdsec cscli decisions add -r 203.0.113.9/32 -d 4h -R "e2e upgrade" >/dev/null
sleep 15
ids > "$OUT/ids-old.txt"
docker stop -t 40 "$UPG" >/dev/null
ulogs > "$OUT/old.log"
echo "  $FROM: $(grep -c . "$OUT/ids-old.txt") managed objects"

# --- 2. this checkout on the same database -------------------------------------
step "2. checkout on the $FROM database"
upg_run "$NEW_IMAGE"
wait_for 120 "checkout ready on the old database" ready || { ulogs | tail -20; exit 1; }
check "host-prefix ban migrated (logged once)" sh -c "[ \"\$(docker logs $UPG 2>&1 | grep -c 'rekeyed bans stored as /32')\" = 1 ]"
check "migration count is 1" sh -c "docker logs $UPG 2>&1 | grep 'rekeyed bans' | grep -q '\"bans\":1'"
wait_for 60 "203.0.113.9 now enforced as a bare address" has_ip v4 203.0.113.9
check "no /32 member on UniFi" sh -c "! (groups | node q.js \"data.flatMap(g => g.group_members)\" | grep -q '/32$')"
check "all 45 old v4 bans still on UniFi" all_old
check "old v6 ban still on UniFi" has_ip v6 2001:db8::1
check "old feed ban still on UniFi" has_ip v4 198.51.100.200
sleep 25 # one reconcile interval (bouncer.env: 20s)
ids > "$OUT/ids-new.txt"
missing=$(comm -23 "$OUT/ids-old.txt" "$OUT/ids-new.txt")
[ -z "$missing" ] && ok "every $FROM group and rule kept (same IDs)" || { bad "objects replaced or removed:"; echo "$missing" | sed 's/^/    /'; }
added=$(comm -13 "$OUT/ids-old.txt" "$OUT/ids-new.txt")
[ -z "$added" ] && ok "no duplicate groups or rules" || { bad "new objects after upgrade:"; echo "$added" | sed 's/^/    /'; }
[ "$(metric 'crowdsec_unifi_unsynced_ips{family="v4"')" = 0 ] && ok "no unenforced bans" || bad "unsynced_ips=$(metric 'crowdsec_unifi_unsynced_ips{family="v4"')"
[ "$(metric 'crowdsec_unifi_circuit_breaker_open')" = 0 ] && ok "circuit breaker closed" || bad "circuit breaker open"

# --- 3. bans from the old database still behave --------------------------------
step "3. old bans after the upgrade"
undecide 192.0.2.200
wait_for 60 "unban of a $FROM ban releases it" lacks_ip v4 192.0.2.200
decide 192.0.2.201 1h
wait_for 60 "new ban lands" has_ip v4 192.0.2.201
docker restart "$UPG" >/dev/null
wait_for 120 "ready after a second start" ready
check "migration not repeated" sh -c "[ \"\$(docker logs $UPG 2>&1 | grep -c 'rekeyed bans stored as /32')\" = 1 ]"
check "no error-level log lines" sh -c "! docker logs $UPG 2>&1 | grep -q '\"level\":\"error\"'"
