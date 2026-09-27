#!/usr/bin/env bash
# Live end-to-end suite: a real UniFi Network Application (linuxserver image,
# MongoDB 7), a real CrowdSec LAPI, a blocklist/webhook mock, and the bouncer
# image built from this checkout with production security flags.
# Manual, not run in CI. See README.md.
#
#   bash e2e.local/run.sh                 full suite
#   KEEP=1 bash e2e.local/run.sh          leave the stack running afterwards
#   E2E_UNIFI_API_KEY=... bash e2e.local/run.sh
#                                         also run the API-key checks (create the
#                                         key in the controller UI first)
set -u
cd "$(dirname "$0")"
. ./lib.sh
single_run

docker info >/dev/null 2>&1 || { echo "Docker is not running"; exit 2; }

step "0. Build and start the stack"
stack_up
$DC up -d --build bouncer >/dev/null 2>&1 || { echo "bouncer failed to start"; $DC logs bouncer --tail 50; exit 1; }
wait_for 90 "bouncer /readyz 200" ready

step "1. Startup against a self-hosted controller"
check "/healthz 200" healthy
check "detected standalone controller layout" sh -c "$DC logs bouncer --no-log-prefix 2>&1 | grep -q '\"layout\":\"standalone\"'"
check "FIREWALL_MODE=auto resolved without error" sh -c "! $DC logs bouncer --no-log-prefix 2>&1 | grep -q 'resolve mode'"
check "no Cloudflare drain noise without an API key" sh -c "! $DC logs bouncer --no-log-prefix 2>&1 | grep -q 'Cloudflare drain'"
check "healthcheck subcommand exits 0" bexec healthcheck
check "CrowdSec client lines are JSON" sh -c "! $DC logs bouncer --no-log-prefix 2>&1 | grep -q '^time='"

step "2. IPv4 ban creates a group and a WAN_IN drop rule"
decide 203.0.113.10
wait_for 30 "203.0.113.10 in crowdsec-block-v4 group" has_ip v4 203.0.113.10
rule=$(rules | q "data.find(r => r.name === 'crowdsec-drop-v4-0')")
gid=$(groups | q "data.find(g => g.name === 'crowdsec-block-v4-0')._id")
echo "$rule" | q "d.ruleset === 'WAN_IN' && d.action === 'drop' && d.enabled" | grep -qx true \
  && ok "rule is an enabled WAN_IN drop" || bad "rule: $rule"
echo "$rule" | q "d.src_firewallgroup_ids.includes('$gid')" | grep -qx true \
  && ok "rule references the group" || bad "rule does not reference group $gid"

step "3. IPv6 ban uses a separate group and WANv6_IN rule"
decide 2001:db8::10
wait_for 30 "2001:db8::10 in crowdsec-block-v6 group" has_ip v6 2001:db8::10
rules | q "data.some(r => r.name.startsWith('crowdsec-drop-v6-') && r.ruleset === 'WANv6_IN')" | grep -qx true \
  && ok "WANv6_IN rule present" || bad "no WANv6_IN rule"

step "4. Unban removes the address"
undecide 203.0.113.10
wait_for 30 "203.0.113.10 removed" lacks_ip v4 203.0.113.10

step "5. Filters: private, whitelisted"
decide 10.20.30.40
decide 198.51.100.250
decide 203.0.113.11
wait_for 30 "control IP 203.0.113.11 applied" has_ip v4 203.0.113.11
check "private 10.20.30.40 never sent" lacks_ip v4 10.20.30.40
check "whitelisted 198.51.100.250 never sent" lacks_ip v4 198.51.100.250
[ "$(metric 'crowdsec_unifi_decisions_filtered_total')" != 0 ] && ok "filtered decisions counted" || bad "no filtered metric"

step "5b. Single-address range bans land as bare addresses"
# UniFi rejects x/32 and x/128 group members (api.err.FirewallGroupInvalidArgs).
# Before the fix one such range ban failed every sync until the circuit breaker
# opened and no further ban was applied.
$DC exec -T crowdsec cscli decisions add -r 203.0.113.77/32 -d 1h -R "e2e range" >/dev/null
$DC exec -T crowdsec cscli decisions add -r 2001:db8::77/128 -d 1h -R "e2e range" >/dev/null
wait_for 30 "range 203.0.113.77/32 applied as 203.0.113.77" has_ip v4 203.0.113.77
wait_for 30 "range 2001:db8::77/128 applied as 2001:db8::77" has_ip v6 2001:db8::77
sleep 15
decide 203.0.113.78
wait_for 30 "a later ban 203.0.113.78 still applies" has_ip v4 203.0.113.78
check "controller never rejected a group member" sh -c "! $DC logs bouncer --no-log-prefix 2>&1 | grep -q 'FirewallGroupInvalidArgs'"
[ "$(metric 'crowdsec_unifi_circuit_breaker_open')" = 0 ] && ok "circuit breaker closed" || bad "circuit breaker open"

step "6. Sharding at FIREWALL_GROUP_CAPACITY_V4=40"
seq 1 100 | sed 's/^/192.0.2./' > .bulk.txt
seq 1 5 | sed 's/^/198.18.0./' >> .bulk.txt
for ip in $(cat .bulk.txt); do echo "$ip"; done | awk '{print "{\"value\":\"" $1 "\",\"duration\":\"1h\",\"reason\":\"e2e bulk\",\"type\":\"ban\",\"scope\":\"ip\"}"}' \
  | node -e 'let s="";process.stdin.on("data",c=>s+=c).on("end",()=>console.log("["+s.trim().split("\n").join(",")+"]"))' > .bulk.json
docker cp .bulk.json csue2e-crowdsec-1:/tmp/bulk.json >/dev/null
import_bulk() { $DC exec -T crowdsec cscli decisions import -i /tmp/bulk.json --format json >/dev/null 2>&1 || bad "cscli decisions import failed"; }
all_bulk() { [ "$(managed_members v4 | grep -cE '^(192\.0\.2\.|198\.18\.0\.)')" -ge 105 ]; }
# CrowdSec stores created_at in whole seconds but advances the stream cursor
# with sub-second precision, so a pull that lands during the import's second
# can skip the whole import (upstream behaviour; a bouncer restart recovers
# it). Import once more if nothing arrives; the check below still requires
# the bouncer to apply every address.
sleep 3
import_bulk
for _ in $(seq 1 30); do all_bulk && break; sleep 2; done
if ! all_bulk; then
  echo "  (bulk import not streamed by the LAPI; importing again)"
  sleep 2
  import_bulk
fi
wait_for 120 "all 105 bulk IPs applied" all_bulk
n=$(group_count v4); [ "$n" -ge 3 ] && ok "$n v4 shards for 107+ IPs" || bad "only $n v4 shards"
[ "$(rule_count v4)" = "$n" ] && ok "one drop rule per v4 shard" || bad "rules=$(rule_count v4) shards=$n"
dups=$(managed_members v4 | sort | uniq -d | wc -l | tr -d ' ')
[ "$dups" = 0 ] && ok "no IP stored in two shards" || bad "$dups duplicate IPs across shards"
over=$(groups | q "data.filter(g => g.name.startsWith('crowdsec-block-v4-') && g.group_members.length > 40).length")
[ "$over" = 0 ] && ok "no shard over capacity" || bad "$over shards over capacity"

step "7. Blocklist feed (URL carries a token)"
wait_for 60 "blocklist IP 198.51.100.200 applied" has_ip v4 198.51.100.200
check "feed token never logged" sh -c "! $DC logs bouncer --no-log-prefix 2>&1 | grep -q '$FEED_TOKEN'"
curl -s -X PUT --data-binary $'198.51.100.201\n198.51.100.202 ; SBL123 inline comment\n198.51.100.203/32 # host prefix\n' \
  http://127.0.0.1:18080/_blocklist >/dev/null
echo "  (feed now drops 198.51.100.200; expiry is 2x refresh, not immediate)"
wait_for 60 "feed line with an inline comment applied" has_ip v4 198.51.100.202
wait_for 30 "feed host prefix 198.51.100.203/32 applied as a bare address" has_ip v4 198.51.100.203

step "7b. Feed outage keeps the feed's bans"
# Feed claims last 2x BLOCKLIST_REFRESH_INTERVAL (20s here). Before the fix a
# feed that stayed down that long lost every ban it had applied.
curl -s -X PUT --data-binary '503' http://127.0.0.1:18080/_feedstatus >/dev/null
sleep 60
check "198.51.100.201 kept through a 60s feed outage" has_ip v4 198.51.100.201
check "198.51.100.202 kept through a 60s feed outage" has_ip v4 198.51.100.202
check "outage logged as keeping bans" sh -c "$DC logs bouncer --no-log-prefix 2>&1 | grep -q 'keeping bans from the last successful fetch'"
curl -s -X PUT --data-binary $'<html>maintenance</html>\n' http://127.0.0.1:18080/_blocklist >/dev/null
curl -s -X PUT --data-binary '0' http://127.0.0.1:18080/_feedstatus >/dev/null
sleep 50
check "a 200 with no valid entries keeps the bans too" has_ip v4 198.51.100.201
curl -s -X PUT --data-binary $'198.51.100.201\n198.51.100.202 ; SBL123\n198.51.100.203/32\n' http://127.0.0.1:18080/_blocklist >/dev/null

step "8. Drift repair by periodic reconcile"
# Empty every v4 shard out of band: >= 100 missing IPs also crosses the
# reconcile_drift webhook threshold.
for gid in $(groups | q "data.filter(g => g.name.startsWith('crowdsec-block-v4-')).map(g => g._id).join(' ')"); do
  grp=$(groups | q "data.find(g => g._id === '$gid')")
  api PUT "/api/s/$SITE/rest/firewallgroup/$gid" "$(echo "$grp" | q "Object.assign({}, d, {group_members: []})")" >/dev/null
done
check "v4 shards emptied out of band" lacks_ip v4 203.0.113.11
all_back() { [ "$(managed_members v4 | wc -l | tr -d ' ')" -ge 105 ] && has_ip v4 203.0.113.11; }
wait_for 90 "reconcile restored every emptied IP" all_back
rid=$(rules | q "data.find(r => r.name === 'crowdsec-drop-v4-0')._id")
api DELETE "/api/s/$SITE/rest/firewallrule/$rid" >/dev/null
recreated() { [ "$(rules | q "data.filter(r => r.name === 'crowdsec-drop-v4-0').length")" = 1 ]; }
wait_for 60 "reconcile recreated deleted drop rule" recreated
wait_for 30 "reconcile_drift webhook delivered" sh -c "curl -s http://127.0.0.1:18080/_webhooks | grep -q reconcile_drift"

step "9. Decision expiry"
decide 203.0.113.12 15s
wait_for 30 "short ban 203.0.113.12 applied" has_ip v4 203.0.113.12
wait_for 90 "expired ban 203.0.113.12 removed" lacks_ip v4 203.0.113.12

step "10. Restart keeps state without duplicating objects"
g_before=$(group_count v4); r_before=$(rule_count v4)
restart_bouncer "bouncer ready after restart"
sleep 5
[ "$(group_count v4)" = "$g_before" ] && ok "group count stable ($g_before)" || bad "groups $g_before -> $(group_count v4)"
[ "$(rule_count v4)" = "$r_before" ] && ok "rule count stable ($r_before)" || bad "rules $r_before -> $(rule_count v4)"
check "IPs survive restart" has_ip v4 203.0.113.11

step "10b. Lost shard: a new shard never reuses a taken number"
# Reproduces a v1.2.5 production failure: shard v4-1 disappears, the bouncer
# restarts without its cache, and the next overflow shard must not be named
# after one that exists (v1.2.5 used len(shards) and retried the duplicate
# create forever, leaving the overflow bans unenforced). It also checks that a
# wiped ban database does not strip enforced bans before the LAPI resends them.
above=$(groups | q "(data.find(g => g.name === 'crowdsec-block-v4-2') || {})._id")
[ -n "$above" ] && [ "$above" != undefined ] && ok "a shard above the gap exists (v4-2)" || bad "precondition: no crowdsec-block-v4-2 before the gap is made"
save_logs
$DC stop bouncer >/dev/null 2>&1
$DC rm -f bouncer >/dev/null 2>&1
rid=$(rules | q "(data.find(r => r.name === 'crowdsec-drop-v4-1') || {})._id")
[ -n "$rid" ] && [ "$rid" != undefined ] && api DELETE "/api/s/$SITE/rest/firewallrule/$rid" >/dev/null
gid=$(groups | q "(data.find(g => g.name === 'crowdsec-block-v4-1') || {})._id")
[ -n "$gid" ] && [ "$gid" != undefined ] && api DELETE "/api/s/$SITE/rest/firewallgroup/$gid" >/dev/null
docker volume rm csue2e_bouncer-data >/dev/null 2>&1
check "shard v4-1 deleted out of band" sh -c "[ \"\$(bash ./api.sh GET /api/s/$SITE/rest/firewallgroup | node ./q.js \"data.some(g => g.name === 'crowdsec-block-v4-1')\")\" = false ]"
$DC up -d bouncer >/dev/null 2>&1
wait_for 90 "bouncer ready with an empty cache" ready
wait_for 120 "every bulk IP applied again" all_bulk
now=$(groups | q "(data.find(g => g.name === 'crowdsec-block-v4-2') || {})._id")
[ "$now" = "$above" ] && ok "v4-2 kept its ID (never emptied or pruned)" || bad "v4-2 was replaced: $above -> $now"
check "no shard pruned while the ban database refilled" sh -c "! $DC logs bouncer --no-log-prefix 2>&1 | grep -q 'pruned empty shard'"
dups=$(groups | q "data.filter(g => g.name.startsWith('crowdsec-block-v4-')).map(g => g.name)" | sort | uniq -d | wc -l | tr -d ' ')
[ "$dups" = 0 ] && ok "no duplicate shard names" || bad "$dups duplicate shard names"
echo "  v4 shards: $(groups | q "data.filter(g => g.name.startsWith('crowdsec-block-v4-')).map(g => g.name).sort().join(' ')")"
n=$(group_count v4)
wait_for 60 "one drop rule per v4 shard ($n)" sh -c "[ \"\$(bash ./api.sh GET /api/s/$SITE/rest/firewallrule | node ./q.js \"data.filter(r => r.name.startsWith('crowdsec-drop-v4-')).length\")\" = $n ]"
[ "$(metric 'crowdsec_unifi_shard_create_failures_total')" = 0 ] && ok "no failed shard creates" || bad "shard creates failed: $(metric 'crowdsec_unifi_shard_create_failures_total')"
[ "$(metric 'crowdsec_unifi_unsynced_ips{family="v4"')" = 0 ] && ok "no unenforced bans" || bad "unsynced_ips=$(metric 'crowdsec_unifi_unsynced_ips{family="v4"')"
check "/readyz 200" ready
# The classic API drops rule descriptions; that must not rewrite every rule.
check "no needless rule rewrites" sh -c "! $DC logs bouncer --no-log-prefix 2>&1 | grep -q 'repaired legacy firewall rule settings'"

step "11. Controller outage and recovery"
$DC stop unifi >/dev/null 2>&1
decide 203.0.113.13
sleep 10
check "bouncer still serving /healthz during outage" healthy
$DC start unifi >/dev/null 2>&1
wait_for 300 "controller back" curl -skf https://127.0.0.1:18443/status
wait_for 120 "queued ban 203.0.113.13 synced after recovery" has_ip v4 203.0.113.13

step "12. Operator CLI while the daemon runs"
# status/ban/unban open the database, which the daemon holds; they must fail
# fast with a clear message (they are tested offline in step 16).
out=$(timeout 60 $DC exec -T bouncer /cs-unifi-bouncer-pro status 2>&1); rc=$?
[ $rc != 0 ] && echo "$out" | grep -q "stop the running bouncer" && ok "status explains the database is in use" || bad "status rc=$rc: $(echo "$out" | tail -2)"
out=$(bexec validate 2>&1); rc=$?
[ $rc = 0 ] && ok "validate exits 0" || bad "validate rc=$rc: $(echo "$out" | tail -2)"
out=$(timeout 60 $DC exec -T bouncer /cs-unifi-bouncer-pro diagnose 2>&1); rc=$?
[ $rc = 0 ] && ok "diagnose exits 0" || bad "diagnose rc=$rc: $(echo "$out" | tail -3)"

step "13. Metrics and log hygiene"
for m in decisions_processed_total api_calls_total active_bans shard_ip_count last_sync_timestamp_seconds circuit_breaker_open; do
  metrics | grep -q "^crowdsec_unifi_$m" && ok "metric $m exported" || bad "metric $m missing"
done
logs=$(blogs)
echo "$logs" | grep -q "$LAPI_KEY"   && bad "LAPI key in logs"        || ok "LAPI key not logged"
echo "$logs" | grep -q "$UNIFI_PASS" && bad "UniFi password in logs"  || ok "UniFi password not logged"
echo "$logs" | grep -qi 'panic'      && bad "panic in logs"           || ok "no panics"

step "14. API-key mode"
if [ -n "${E2E_UNIFI_API_KEY:-}" ]; then
  E2E_UNIFI_API_KEY=$E2E_UNIFI_API_KEY restart_bouncer "bouncer ready with an API key"
  check "API key not logged" sh -c "! $DC logs bouncer --no-log-prefix 2>&1 | grep -qF '$E2E_UNIFI_API_KEY'"
  decide 203.0.113.15
  wait_for 30 "ban applied with API-key auth" has_ip v4 203.0.113.15
else
  skip "needs a UniFi OS console: the self-hosted Network Application cannot issue integration keys or hold zones"
fi

step "15. Dry run sends no writes"
before=$(groups | q "JSON.stringify(data.map(g => [g.name, g.group_members.length]).sort())")
E2E_DRY_RUN=true restart_bouncer "dry-run bouncer ready"
decide 203.0.113.16
sleep 15
after=$(groups | q "JSON.stringify(data.map(g => [g.name, g.group_members.length]).sort())")
[ "$before" = "$after" ] && ok "controller unchanged in dry run" || bad "dry run changed groups"
restart_bouncer "bouncer ready after dry run"

step "16. Graceful shutdown and drain"
save_logs
$DC stop bouncer >/dev/null 2>&1
code=$(docker inspect -f '{{.State.ExitCode}}' csue2e-bouncer-1)
[ "$code" = 0 ] && ok "exit code 0 on SIGTERM" || bad "exit code $code"
out=$(offline status 2>&1); rc=$?
[ $rc = 0 ] && ok "offline status exits 0" || bad "offline status rc=$rc: $(echo "$out" | tail -2)"
out=$(offline ban 203.0.113.14 --duration 1h 2>&1); rc=$?
if [ $rc = 0 ]; then check "offline ban 203.0.113.14 applied" has_ip v4 203.0.113.14
else bad "offline ban rc=$rc: $(echo "$out" | tail -2)"; fi
out=$(offline unban 203.0.113.14 2>&1); rc=$?
if [ $rc = 0 ]; then check "offline unban 203.0.113.14 removed" lacks_ip v4 203.0.113.14
else bad "offline unban rc=$rc: $(echo "$out" | tail -2)"; fi
out=$(offline drain --force 2>&1); rc=$?
[ $rc = 0 ] && ok "drain exits 0" || bad "drain rc=$rc: $(echo "$out" | tail -3)"
left=$(( $(groups | q "data.filter(o => o.name.startsWith('crowdsec-')).length") + $(rules | q "data.filter(o => o.name.startsWith('crowdsec-')).length") ))
[ "${left:-1}" = 0 ] && ok "drain removed every crowdsec-* group and rule" || bad "$left managed objects left after drain"

echo
echo "RESULT: $PASS passed, $FAIL failed, $SKIP skipped (UniFi Network $version)"
webhooks > webhooks.json 2>/dev/null
rm -f .bulk.txt .bulk.json .run.pid
if [ "${KEEP:-0}" = 1 ]; then
  echo "Stack left running (KEEP=1). Controller UI: https://127.0.0.1:18443 (e2eadmin / $UNIFI_PASS)"
else
  $DC down -v --remove-orphans >/dev/null 2>&1
fi
[ "$FAIL" -eq 0 ]
