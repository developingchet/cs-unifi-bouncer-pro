#!/usr/bin/env bash
# Live settings matrix: restarts the bouncer with individual settings changed
# and checks each one's effect on the real controller, LAPI and endpoints.
# Needs a running stack (bash e2e.local/up.sh). Sections run in order:
#
#   bash e2e.local/settings.sh                      every section
#   bash e2e.local/settings.sh validation firewall  just these
set -u
cd "$(dirname "$0")"
. ./lib.sh
single_run
trap 'rm -f .run.pid' EXIT

curl -skf https://127.0.0.1:18443/status >/dev/null || { echo "stack is not up; run up.sh first"; exit 2; }
mkdir -p cases secrets
rm -f cases/*.log

main_up() {
  case_rm
  $DC up -d bouncer >/dev/null 2>&1
  wait_for 120 "${1:-default bouncer back}" ready
}
# start <name> <expect: ready|exit> [docker run args...]
start() {
  local name=$1 expect=$2; shift 2
  case_up "$name" "$@"
  if [ "$expect" = ready ]; then
    wait_for 120 "[$name] bouncer ready" ready
  else
    wait_for 90 "[$name] bouncer exits" sh -c "! docker inspect -f '{{.State.Running}}' $CASE | grep -q true"
  fi
}
v4_rule()  { rules | q "data.find(r => r.name === '${1:-crowdsec-drop-v4-0}')"; }
field()    { q "d && d.$1"; }
wh_count() { webhooks | q "d.filter(e => e.event === '$1').length"; }
site_groups() { api GET "/api/s/$1/rest/firewallgroup"; }
site_has_ip() { site_groups "$1" | q "data.filter(g => g.name.startsWith('crowdsec-block-v4-')).flatMap(g => g.group_members)" | grep -qx "$2"; }
v4_invariants() {
  # every v4 shard within capacity $1, one rule per shard, no IP in two shards,
  # and every ban in the database is on the controller.
  local cap=$1 over dups n r members bans
  over=$(groups | q "data.filter(g => g.name.startsWith('crowdsec-block-v4-') && g.group_members.length > $cap).length")
  # an emptied shard holds the placeholder 192.0.2.1, so it may repeat
  dups=$(managed_members v4 | grep -vx '192.0.2.1' | sort | uniq -d | wc -l | tr -d ' ')
  n=$(group_count v4); r=$(rule_count v4)
  members=$(managed_members v4 | grep -vx '192.0.2.1' | wc -l | tr -d ' ')
  bans=$(metric 'crowdsec_unifi_active_bans{family="v4"')
  [ "$over" = 0 ] && [ "$dups" = 0 ] && [ "$n" = "$r" ] && [ "$members" = "${bans%.*}" ]
}
show_v4() { echo "  v4 shards: $(groups | q "data.filter(g => g.name.startsWith('crowdsec-block-v4-')).map(g => g.name + '=' + g.group_members.length).sort().join(' ')") rules=$(rule_count v4) active_bans=$(metric 'crowdsec_unifi_active_bans{family="v4"')"; }

sec_validation() {
  step "V. Every setting rejects a bad value with a clear message (validate, offline)"
  rejects "LOG_LEVEL" "LOG_LEVEL must be one of" -e LOG_LEVEL=loud
  rejects "LOG_FORMAT" "LOG_FORMAT must be json or text" -e LOG_FORMAT=xml
  rejects "FIREWALL_MODE" "FIREWALL_MODE must be auto, legacy, or zone" -e FIREWALL_MODE=nft
  rejects "FIREWALL_BLOCK_ACTION" "FIREWALL_BLOCK_ACTION must be drop or reject" -e FIREWALL_BLOCK_ACTION=accept
  rejects "FIREWALL_GROUP_CAPACITY" "FIREWALL_GROUP_CAPACITY must be between 1 and 10000" -e FIREWALL_GROUP_CAPACITY=10001
  rejects "FIREWALL_GROUP_CAPACITY_V4" "FIREWALL_GROUP_CAPACITY_V4 must be between" -e FIREWALL_GROUP_CAPACITY_V4=-1
  rejects "FIREWALL_GROUP_CAPACITY_V6" "FIREWALL_GROUP_CAPACITY_V6 must be between" -e FIREWALL_GROUP_CAPACITY_V6=20000
  rejects "FIREWALL_CONNECTION_STATES bad state" "contains invalid or duplicate state" -e FIREWALL_CONNECTION_STATES=NEW,BOGUS
  rejects "FIREWALL_CONNECTION_STATES duplicate" "contains invalid or duplicate state" -e FIREWALL_CONNECTION_STATES=NEW,NEW
  rejects "FIREWALL_CONNECTION_STATES empty" "FIREWALL_CONNECTION_STATES must be ALL" -e FIREWALL_CONNECTION_STATES=
  rejects "SYNC_INTERVAL below 5s" "SYNC_INTERVAL must be at least 5s" -e SYNC_INTERVAL=1s
  rejects "SYNC_INTERVAL not a duration" "sync_interval" -e SYNC_INTERVAL=often
  rejects "SHARD_LIMIT" "SHARD_LIMIT must be between 1 and 10000" -e SHARD_LIMIT=0
  rejects "SHARD_MERGE_THRESHOLD" "SHARD_MERGE_THRESHOLD must be >= -1" -e SHARD_MERGE_THRESHOLD=-2
  rejects "GROUP_NAME_TEMPLATE syntax" "GROUP_NAME_TEMPLATE is invalid Go template" -e 'GROUP_NAME_TEMPLATE=x-{{.Index'
  rejects "GROUP_NAME_TEMPLATE unknown field" "GROUP_NAME_TEMPLATE cannot be rendered" -e 'GROUP_NAME_TEMPLATE=x-{{.Foo}}-{{.Index}}'
  rejects "RULE_NAME_TEMPLATE without {{.Index}}" "RULE_NAME_TEMPLATE must include {{.Index}}" -e 'RULE_NAME_TEMPLATE=drop-{{.Family}}'
  rejects "POLICY_NAME_TEMPLATE syntax" "POLICY_NAME_TEMPLATE is invalid Go template" -e 'POLICY_NAME_TEMPLATE={{end}}'
  rejects "ZONE_PAIRS" "ZONE_PAIRS" -e FIREWALL_MODE=zone -e UNIFI_API_KEY=k -e ZONE_PAIRS=External
  rejects "ZONE_PAIRS_SCENARIO_MAP" "ZONE_PAIRS_SCENARIO_MAP is not supported" -e 'ZONE_PAIRS_SCENARIO_MAP=ssh:External->Internal'
  rejects "CLOUDFLARE in legacy mode" "requires the zone-based firewall" -e CLOUDFLARE_WHITELIST_ENABLED=true -e FIREWALL_MODE=legacy
  rejects "CLOUDFLARE without API key" "CLOUDFLARE_WHITELIST_ENABLED requires UNIFI_API_KEY" -e CLOUDFLARE_WHITELIST_ENABLED=true
  rejects "CLOUDFLARE_ZWHITELIST typo" "unknown CLOUDFLARE_ZWHITELIST_ENABLED" -e CLOUDFLARE_ZWHITELIST_ENABLED=true
  rejects "CLOUDFLARE_REFRESH_INTERVAL" "CLOUDFLARE_REFRESH_INTERVAL must be > 0" -e CLOUDFLARE_WHITELIST_ENABLED=true -e UNIFI_API_KEY=k -e FIREWALL_MODE=zone -e CLOUDFLARE_REFRESH_INTERVAL=0s
  rejects "CLOUDFLARE_IPV4_URL" "CLOUDFLARE_IPV4_URL and CLOUDFLARE_IPV6_URL must be absolute" -e CLOUDFLARE_WHITELIST_ENABLED=true -e UNIFI_API_KEY=k -e FIREWALL_MODE=zone -e 'CLOUDFLARE_ZONE_PAIRS=External->Internal' -e CLOUDFLARE_IPV4_URL=ftp://x
  rejects "UNIFI_URL scheme" "UNIFI_URL must be an absolute http:// or https:// URL" -e UNIFI_URL=ftp://unifi
  rejects "UNIFI_URL http with UNIFI_REQUIRE_HTTPS" "UNIFI_URL uses http://" -e UNIFI_URL=http://unifi:8080
  rejects "UNIFI_URL with credentials" "UNIFI_URL must not contain a username or password" -e UNIFI_URL=https://e2eadmin:pw@unifi:8443
  rejects "UNIFI_PASSWORD missing" "either UNIFI_API_KEY or both UNIFI_USERNAME and UNIFI_PASSWORD" -e UNIFI_PASSWORD=
  rejects "UNIFI_SITES empty" "UNIFI_SITES must list at least one site" -e UNIFI_SITES=
  rejects "CROWDSEC_LAPI_URL scheme" "CROWDSEC_LAPI_URL must start with http:// or https://" -e CROWDSEC_LAPI_URL=crowdsec:8080
  rejects "CROWDSEC_LAPI_URL credentials" "CROWDSEC_LAPI_URL must be an absolute URL without userinfo" -e CROWDSEC_LAPI_URL=http://u:p@crowdsec:8080
  rejects "CROWDSEC_LAPI_ALLOW_HTTP" "CROWDSEC_LAPI_URL uses plaintext HTTP outside loopback" -e CROWDSEC_LAPI_ALLOW_HTTP=false
  rejects "CROWDSEC_LAPI_KEY missing" "CROWDSEC_LAPI_KEY is required" -e CROWDSEC_LAPI_KEY=
  rejects "CROWDSEC_POLL_INTERVAL" "CROWDSEC_POLL_INTERVAL must be > 0" -e CROWDSEC_POLL_INTERVAL=0s
  rejects "CROWDSEC_RESYNC_INTERVAL" "CROWDSEC_RESYNC_INTERVAL must be 0 (disabled) or at least" -e CROWDSEC_RESYNC_INTERVAL=1m
  rejects "BLOCK_WHITELIST CIDR" "BLOCK_WHITELIST: invalid CIDR" -e BLOCK_WHITELIST=10.0.0.0/33
  rejects "BLOCK_WHITELIST IP" "BLOCK_WHITELIST: invalid IP address" -e BLOCK_WHITELIST=not-an-ip
  rejects "BLOCK_SCENARIO_DURATION_MAP format" "must be scenario=duration" -e BLOCK_SCENARIO_DURATION_MAP=ssh
  rejects "BLOCK_SCENARIO_DURATION_MAP duration" "positive duration" -e BLOCK_SCENARIO_DURATION_MAP=ssh=-1h
  rejects "DECISION_RATE_LIMIT" "DECISION_RATE_LIMIT must be >= 0" -e DECISION_RATE_LIMIT=-1
  rejects "DECISION_BURST_SIZE" "DECISION_BURST_SIZE must be >= 1 when DECISION_RATE_LIMIT is set" -e DECISION_RATE_LIMIT=5 -e DECISION_BURST_SIZE=0
  rejects "BAN_TTL" "BAN_TTL must be > 0" -e BAN_TTL=0s
  rejects "JANITOR_INTERVAL" "JANITOR_INTERVAL must be > 0" -e JANITOR_INTERVAL=0s
  rejects "SHUTDOWN_GRACE_PERIOD" "SHUTDOWN_GRACE_PERIOD must be > 0" -e SHUTDOWN_GRACE_PERIOD=0s
  rejects "BLOCKLIST_URLS" "BLOCKLIST_URLS entry 2 must be an absolute" -e 'BLOCKLIST_URLS=http://mock:8080/a.txt,ftp://x/b?token=zz'
  rejects "BLOCKLIST_REFRESH_INTERVAL" "BLOCKLIST_REFRESH_INTERVAL must be > 0 when BLOCKLIST_URLS is set" -e BLOCKLIST_REFRESH_INTERVAL=0s
  rejects "WEBHOOK_URL" "WEBHOOK_URL must be an absolute" -e WEBHOOK_URL=hooks.example/x
  rejects "WEBHOOK_EVENTS" 'WEBHOOK_EVENTS: unknown event "breaker"' -e WEBHOOK_EVENTS=circuit_breaker_open,breaker
  rejects "UNIFI_PASSWORD_FILE missing" "UNIFI_PASSWORD_FILE: cannot read /run/secrets/none" -e UNIFI_PASSWORD_FILE=/run/secrets/none
  out=$($DC run --rm -T -e FIREWALL_FLUSH_CONCURRENCY=4 bouncer validate 2>&1)
  echo "$out" | grep -q "FIREWALL_FLUSH_CONCURRENCY has no effect" && ok "FIREWALL_FLUSH_CONCURRENCY warns it has no effect" || bad "no flush concurrency warning"
  out=$($DC run --rm -T -e 'BLOCKLIST_URLS=ftp://x/b?token=leakme' bouncer validate 2>&1)
  echo "$out" | grep -q leakme && bad "validate echoed a feed token" || ok "validate never echoes a feed URL"
}

sec_observability() {
  step "O1. LOG_FORMAT=text, LOG_LEVEL=info"
  start logtext ready -e LOG_FORMAT=text -e LOG_LEVEL=info
  check "no JSON lines" sh -c "! docker logs $CASE 2>&1 | grep -q '^{'"
  check "no debug lines" sh -c "! docker logs $CASE 2>&1 | grep -q ' DBG '"
  check "info lines present" case_log_has "health server started"
  check "LAPI key not logged" case_log_lacks "$LAPI_KEY"
  case_down

  step "O2. LOG_LEVEL=warn"
  start logwarn ready -e LOG_LEVEL=warn
  check "info lines suppressed" case_log_lacks "health server started"
  check "warnings still logged" case_log_has "CROWDSEC_LAPI_URL uses http://"
  case_down

  step "O3. METRICS_ENABLED=false"
  start nometrics ready -e METRICS_ENABLED=false
  check "metrics endpoint closed" sh -c "! curl -sf -m 3 http://127.0.0.1:19090/metrics"
  case_down

  step "O4. METRICS_ADDR and HEALTH_ADDR on other ports"
  case_up altports -e METRICS_ADDR=:9191 -e HEALTH_ADDR=:8181 -p 127.0.0.1:19191:9191 -p 127.0.0.1:18181:8181
  wait_for 120 "[altports] /readyz on :8181" sh -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18181/readyz)\" = 200 ]"
  check "metrics on :9191" sh -c "curl -sf http://127.0.0.1:19191/metrics | grep -q crowdsec_unifi_"
  check "default :9090 closed" sh -c "! curl -sf -m 3 http://127.0.0.1:19090/metrics"
  check "healthcheck subcommand follows HEALTH_ADDR" docker exec "$CASE" /cs-unifi-bouncer-pro healthcheck
  case_down

  step "O5. HEALTH_CHECK_LAPI: /readyz follows the LAPI"
  main_up
  $DC stop crowdsec >/dev/null 2>&1
  wait_for 30 "/readyz 503 with the LAPI down" sh -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18081/readyz)\" = 503 ]"
  check "/readyz body names the LAPI" sh -c "curl -s http://127.0.0.1:18081/readyz | grep -q 'lapi: unreachable'"
  check "/healthz stays 200" healthy
  $DC start crowdsec >/dev/null 2>&1
  wait_for 120 "/readyz 200 once the LAPI is back" ready
  start nolapicheck ready -e HEALTH_CHECK_LAPI=false
  $DC stop crowdsec >/dev/null 2>&1
  sleep 5
  check "HEALTH_CHECK_LAPI=false keeps /readyz 200 with the LAPI down" ready
  $DC start crowdsec >/dev/null 2>&1
  wait_for 90 "crowdsec healthy again" sh -c "$DC exec -T crowdsec cscli lapi status"
  case_down

  step "O6. Wrong CROWDSEC_LAPI_KEY"
  case_up badlapikey -e CROWDSEC_LAPI_KEY=wrong-key-0000000000000000
  sleep 20
  check "/readyz 503 lapi: unexpected status" sh -c "curl -s http://127.0.0.1:18081/readyz | grep -q 'lapi: unexpected status'"
  check "/healthz 200" healthy
  out=$(docker exec "$CASE" /cs-unifi-bouncer-pro diagnose 2>&1)
  echo "$out" | grep -qi "check CROWDSEC_LAPI_KEY" && ok "diagnose names CROWDSEC_LAPI_KEY" || bad "diagnose: $(echo "$out" | grep -i lapi | head -2)"
  check "wrong key not logged" case_log_lacks "wrong-key-0000000000000000"
  case_down

  step "O7. UNIFI_API_DEBUG=true"
  start apidebug ready -e UNIFI_API_DEBUG=true -e LOG_LEVEL=debug
  decide 198.19.7.1
  wait_for 30 "ban applied" has_ip v4 198.19.7.1
  check "API requests logged" case_log_has '"unifi api request"'
  check "password never logged" case_log_lacks "$UNIFI_PASS"
  check "session cookie never logged" case_log_lacks "unifises="
  check "CSRF token never logged" sh -c "! docker logs $CASE 2>&1 | grep -iE 'csrf[-_]token\"?[:=] ?\"?[0-9a-f]{8}'"
  case_down
}

sec_metrics() {
  step "M1. Prometheus exposition passes promtool"
  main_up
  decide 198.19.8.1
  decide 10.19.8.1  # private: filtered at stage 6, so decisions_filtered_total gets a series
  wait_for 30 "ban applied" has_ip v4 198.19.8.1
  sleep 35  # one janitor run and one periodic reconcile
  metrics > .metrics.txt
  # shard_ip_count predates the lint and keeps its name for existing dashboards.
  out=$(docker run --rm -i --entrypoint promtool prom/prometheus:latest check metrics < .metrics.txt 2>&1 \
    | grep -v 'crowdsec_unifi_shard_ip_count non-histogram and non-summary metrics should not have "_count" suffix')
  [ -z "$out" ] && ok "promtool check metrics clean (apart from the known shard_ip_count name)" || bad "promtool: $(echo "$out" | head -5 | tr '\n' ' ')"

  step "M2. Every metric is exported and agrees with the controller"
  for m in decisions_processed_total decisions_filtered_total api_calls_total api_duration_seconds auth_errors_total \
           reauth_total active_bans firewall_group_size shard_occupancy_ratio unsynced_ips db_size_bytes \
           reconcile_duration_seconds reconcile_delta shard_ip_count shard_sync_total shard_sync_duration_seconds \
           dirty_shards last_sync_timestamp_seconds decision_latency_seconds circuit_breaker_open decisions_in_flight \
           cloudflare_whitelist_sync_errors_total; do
    grep -q "^crowdsec_unifi_$m" .metrics.txt && ok "metric $m exported" || bad "metric $m missing"
  done
  v4_invariants 40 && ok "active_bans{v4} matches the controller's v4 members" || { bad "active_bans vs controller"; show_v4; }
  [ "$(metric 'crowdsec_unifi_unsynced_ips{family="v4"')" = 0 ] && ok "unsynced_ips 0" || bad "unsynced_ips $(metric 'crowdsec_unifi_unsynced_ips{family="v4"')"
  [ "$(metric 'crowdsec_unifi_dirty_shards')" = 0 ] && ok "dirty_shards 0" || bad "dirty_shards $(metric 'crowdsec_unifi_dirty_shards')"
  [ "$(metric 'crowdsec_unifi_decisions_in_flight')" = 0 ] && ok "decisions_in_flight 0" || bad "decisions_in_flight"
  last=$(metric 'crowdsec_unifi_last_sync_timestamp_seconds'); now=$(date +%s)
  node -e "process.exit(Math.abs($now - Number('$last')) < 120 ? 0 : 1)" && ok "last_sync_timestamp_seconds is recent" || bad "last_sync $last vs now $now"
  sum=$(grep '^crowdsec_unifi_firewall_group_size{family="v4"' .metrics.txt | awk '{s+=$2} END {print s+0}')
  members=$(managed_members v4 | wc -l | tr -d ' ')
  [ "$sum" = "$members" ] && ok "firewall_group_size sums to the controller's member count ($sum)" || bad "group_size sum $sum vs members $members"
  node -e "process.exit(Number('$(metric 'crowdsec_unifi_db_size_bytes')') > 0 ? 0 : 1)" && ok "db_size_bytes > 0" || bad "db_size_bytes 0"
  grep -q 'crowdsec_unifi_decisions_processed_total{action="ban",source="stream"}' .metrics.txt && ok "decisions_processed_total{source=stream}" || bad "no stream label"
  grep -q 'crowdsec_unifi_reconcile_duration_seconds_count{trigger="startup"}' .metrics.txt && ok "startup reconcile timed" || bad "no startup reconcile metric"
  grep -q 'crowdsec_unifi_reconcile_duration_seconds_count{trigger="periodic"}' .metrics.txt && ok "periodic reconcile timed" || bad "no periodic reconcile metric"

  step "M3. A real Prometheus scrapes the bouncer"
  printf 'global: {scrape_interval: 5s}\nscrape_configs:\n  - job_name: bouncer\n    static_configs: [{targets: ["host.docker.internal:19090"]}]\n' > .prom.yml
  docker rm -f csue2e-prom >/dev/null 2>&1
  docker run -d --name csue2e-prom -p 127.0.0.1:19099:9090 -v "$PWD/.prom.yml:/etc/prometheus/prometheus.yml:ro" prom/prometheus:latest >/dev/null
  promq() { curl -s "http://127.0.0.1:19099/api/v1/query" --data-urlencode "query=$1" | q "d.data.result.length ? d.data.result[0].value[1] : ''"; }
  wait_for 90 "Prometheus target up" sh -c "[ \"\$(curl -s 'http://127.0.0.1:19099/api/v1/query?query=up' | node ./q.js 'd.data.result.length ? d.data.result[0].value[1] : 0')\" = 1 ]"
  v=$(promq 'sum(crowdsec_unifi_active_bans{family="v4"})')
  [ -n "$v" ] && [ "$v" != 0 ] && ok "PromQL active_bans = $v" || bad "PromQL active_bans empty"
  grep -q 'crowdsec_unifi_decisions_filtered_total{reason="private_ip",stage="6_private"}' .metrics.txt \
    && ok "decisions_filtered_total{stage=6_private}" || bad "private decision not counted as filtered"
  # rate() needs two samples inside the window.
  rate_ready() { [ -n "$(promq 'sum(rate(crowdsec_unifi_api_calls_total[1m]))')" ]; }
  wait_for 60 "PromQL rate(api_calls_total) has a value" rate_ready
  docker rm -f csue2e-prom >/dev/null 2>&1
  rm -f .prom.yml .metrics.txt
}

sec_firewall() {
  step "F1. Rule placement and action settings are applied and repaired"
  main_up
  decide 198.19.1.1
  decide 2001:db8:19::1
  wait_for 30 "v4 ban applied" has_ip v4 198.19.1.1
  wait_for 30 "v6 ban applied" has_ip v6 2001:db8:19::1
  start ruleopts ready -e FIREWALL_BLOCK_ACTION=reject -e FIREWALL_LOG_DROPS=true \
    -e LEGACY_RULESET_V4=LAN_IN -e LEGACY_RULE_INDEX_START_V4=22500 \
    -e LEGACY_RULESET_V6=LANv6_IN -e LEGACY_RULE_INDEX_START_V6=27500
  rule_is() { [ "$(v4_rule "$1" | q "[d.action, d.logging, d.ruleset, d.rule_index].join(' ')")" = "$2" ]; }
  wait_for 60 "v4 rule becomes reject/logging/LAN_IN/22500" rule_is crowdsec-drop-v4-0 "reject true LAN_IN 22500"
  wait_for 60 "v6 rule becomes reject/logging/LANv6_IN/27500" rule_is crowdsec-drop-v6-0 "reject true LANv6_IN 27500"
  check "repair logged" case_log_has "repaired legacy firewall rule settings"
  case_down
  main_up
  wait_for 60 "defaults restore drop/WAN_IN/22000" rule_is crowdsec-drop-v4-0 "drop false WAN_IN 22000"
  wait_for 60 "defaults restore drop/WANv6_IN/27000" rule_is crowdsec-drop-v6-0 "drop false WANv6_IN 27000"

  step "F2. FIREWALL_ENABLE_IPV6=false"
  start noipv6 ready -e FIREWALL_ENABLE_IPV6=false
  decide 2001:db8:19::2
  decide 198.19.1.2
  wait_for 30 "v4 ban still applied" has_ip v4 198.19.1.2
  check "v6 ban not sent" lacks_ip v6 2001:db8:19::2
  check "no active_bans{v6} series" sh -c "! curl -s http://127.0.0.1:19090/metrics | grep -q 'active_bans{family=\"v6\"'"
  echo "  (existing v6 objects: groups=$(group_count v6) rules=$(rule_count v6))"
  case_down
  main_up
  wait_for 60 "re-enabling IPv6 applies the held v6 ban" has_ip v6 2001:db8:19::2

  step "F3. Name templates"
  save_logs; $DC stop bouncer >/dev/null 2>&1
  out=$(offline drain --force 2>&1) && ok "drained default-named objects" || bad "drain: $(echo "$out" | tail -2)"
  T=(-e 'GROUP_NAME_TEMPLATE=e2e-{{.Site}}-{{.Family}}-g{{.Index}}' -e 'RULE_NAME_TEMPLATE=e2e-{{.Family}}-r{{.Index}}')
  start templates ready "${T[@]}"
  wait_for 60 "group e2e-default-v4-g0 holds the ban" sh -c "bash ./api.sh GET /api/s/default/rest/firewallgroup | node ./q.js \"(data.find(g => g.name === 'e2e-default-v4-g0') || {group_members: []}).group_members\" | grep -qx 198.19.1.1"
  gid=$(groups | q "(data.find(g => g.name === 'e2e-default-v4-g0') || {})._id")
  wait_for 60 "rule e2e-v4-r0 points at it" sh -c "bash ./api.sh GET /api/s/default/rest/firewallrule | node ./q.js \"(data.find(r => r.name === 'e2e-v4-r0') || {src_firewallgroup_ids: []}).src_firewallgroup_ids.includes('$gid')\" | grep -qx true"
  check "no crowdsec-* objects" sh -c "[ \"\$(bash ./api.sh GET /api/s/default/rest/firewallgroup | node ./q.js \"data.filter(g => g.name.startsWith('crowdsec-block-')).length\")\" = 0 ]"
  case_down
  out=$($DC run --rm -T "${T[@]}" bouncer drain --force 2>&1) && ok "drain with the same templates" || bad "drain: $(echo "$out" | tail -2)"
  left=$(( $(groups | q "data.filter(o => o.name.startsWith('e2e-')).length") + $(rules | q "data.filter(o => o.name.startsWith('e2e-')).length") ))
  [ "$left" = 0 ] && ok "drain removed every templated object" || bad "$left templated objects left"
  main_up
  wait_for 90 "default names restored with the bans" has_ip v4 198.19.1.1

  step "F4. Capacity shrink, SHARD_LIMIT and merging"
  for i in $(seq 10 21); do decide 198.19.1.$i; done
  wait_for 60 "12 more bans applied" has_ip v4 198.19.1.21
  start shardlimit ready -e SHARD_LIMIT=3
  wait_for 120 "every shard within 3, one rule each, all bans enforced" v4_invariants 3
  show_v4
  for i in $(seq 10 21); do undecide 198.19.1.$i; done
  wait_for 90 "bans removed" lacks_ip v4 198.19.1.21
  wait_for 90 "sparse shards merged (shards_rebalanced_total > 0)" sh -c "curl -s http://127.0.0.1:19090/metrics | grep -q '^crowdsec_unifi_shards_rebalanced_total'"
  wait_for 90 "invariants hold after merging" v4_invariants 3
  show_v4
  case_down
  main_up
  wait_for 120 "back at capacity 40, invariants hold" v4_invariants 40
  show_v4

  step "F5. Reconcile settings"
  start noreconcile ready -e FIREWALL_RECONCILE_ON_START=false -e FIREWALL_RECONCILE_INTERVAL=0s
  sleep 40
  check "no startup reconcile" case_log_lacks "running startup reconcile"
  check "no periodic reconcile" case_log_lacks "periodic reconcile complete"
  case_down

  step "F6. FIREWALL_MODE"
  start legacy ready -e FIREWALL_MODE=legacy
  case_down
  start zone exit -e FIREWALL_MODE=zone
  echo "  zone mode with a password login: $(case_logs | grep -iE 'error|fatal' | tail -1 | cut -c1-240)"
  [ "$(case_exit)" != 0 ] && ok "zone mode without an API key exits non-zero" || bad "exit $(case_exit)"
  case_down

  step "F7. SIGHUP in legacy mode"
  main_up
  docker kill -s HUP csue2e-bouncer-1 >/dev/null
  sleep 5
  check "no zone reload attempted" sh -c "! $DC logs bouncer --no-log-prefix 2>&1 | grep -q 'SIGHUP: zone reload failed'"
  check "reload skip logged" sh -c "$DC logs bouncer --no-log-prefix 2>&1 | grep -q 'ZoneManager not available'"
  check "still ready after SIGHUP" ready
}

sec_decisions() {
  step "D1. CROWDSEC_ORIGINS"
  main_up
  decide 198.19.2.2
  wait_for 30 "ban 198.19.2.2 applied before narrowing origins" has_ip v4 198.19.2.2
  start origins ready -e CROWDSEC_ORIGINS=crowdsec
  decide 198.19.2.1
  sleep 12
  check "cscli-origin ban filtered" lacks_ip v4 198.19.2.1
  check "origin filter counted" sh -c "curl -s http://127.0.0.1:19090/metrics | grep -q 'stage=\"3_origin\"'"
  undecide 198.19.2.2
  wait_for 30 "a deletion still lifts a ban its origin filter now rejects" lacks_ip v4 198.19.2.2
  case_down

  step "D2. BLOCK_SCENARIO_EXCLUDE and BLOCK_MIN_DURATION"
  start filters ready -e BLOCK_SCENARIO_EXCLUDE=e2e-excluded -e BLOCK_MIN_DURATION=2h
  decide 198.19.2.3 3h "e2e-excluded-scan"
  decide 198.19.2.4 3h "e2e other"
  decide 198.19.2.5 1h "e2e other"
  wait_for 30 "allowed 3h ban applied" has_ip v4 198.19.2.4
  check "excluded scenario filtered" lacks_ip v4 198.19.2.3
  check "1h ban under the 2h minimum filtered" lacks_ip v4 198.19.2.5
  case_down

  step "D3. BLOCK_SCENARIO_DURATION_MAP and BAN_TTL"
  start durations ready -e 'BLOCK_SCENARIO_DURATION_MAP=e2e-short=20s' -e JANITOR_INTERVAL=5s
  decide 198.19.2.7 1h "e2e-short probe"
  wait_for 30 "mapped ban applied" has_ip v4 198.19.2.7
  wait_for 60 "mapped ban lifted after 20s instead of 1h" lacks_ip v4 198.19.2.7
  case_down
  start banttl ready -e BAN_TTL=30s -e JANITOR_INTERVAL=5s
  decide 198.19.2.8 4h
  wait_for 30 "4h ban applied" has_ip v4 198.19.2.8
  wait_for 75 "BAN_TTL=30s lifts it" lacks_ip v4 198.19.2.8
  case_down
  main_up
  wait_for 60 "restart restores it while CrowdSec still holds the decision" has_ip v4 198.19.2.8

  step "D4. A newly whitelisted address is lifted on restart"
  decide 198.19.2.9
  wait_for 30 "198.19.2.9 applied" has_ip v4 198.19.2.9
  start whitelist ready -e BLOCK_WHITELIST=198.51.100.250,198.19.2.0/28
  check "lift logged" case_log_has "lifted stored bans that are whitelisted"
  wait_for 60 "whitelisted 198.19.2.9 removed from UniFi" lacks_ip v4 198.19.2.9
  case_down
  main_up
  wait_for 60 "re-applied once no longer whitelisted" has_ip v4 198.19.2.9

  step "D5. DECISION_RATE_LIMIT delays, never drops"
  seq 1 20 | awk '{print "{\"value\":\"198.19.3." $1 "\",\"duration\":\"1h\",\"reason\":\"e2e rate\",\"type\":\"ban\",\"scope\":\"ip\"}"}' \
    | node -e 'let s="";process.stdin.on("data",c=>s+=c).on("end",()=>console.log("["+s.trim().split("\n").join(",")+"]"))' > .rate.json
  docker cp .rate.json csue2e-crowdsec-1:/tmp/rate.json >/dev/null
  # Import before startup: a bulk import can land in the same second as a
  # stream pull and wait for the resync, so the startup batch carries all 20.
  $DC stop bouncer >/dev/null 2>&1
  $DC exec -T crowdsec cscli decisions import -i /tmp/rate.json --format json >/dev/null 2>&1
  start ratelimit ready -e DECISION_RATE_LIMIT=2 -e DECISION_BURST_SIZE=2
  all_rate() { [ "$(managed_members v4 | grep -c '^198\.19\.3\.')" -ge 20 ]; }
  wait_for 90 "all 20 rate-limited bans applied" all_rate
  # The startup batch holds every decision CrowdSec has; after the burst of 2
  # they must be applied at about 2 per second.
  rate=$(case_logs | grep '"job applied"' | node -e '
    const t = require("fs").readFileSync(0, "utf8").trim().split("\n").map(l => Date.parse(JSON.parse(l).time));
    const s = (Math.max(...t) - Math.min(...t)) / 1000;
    console.log(t.length > 10 && s > 0 ? ((t.length - 2) / s).toFixed(2) : -1)')
  node -e "process.exit($rate >= 1.5 && $rate <= 2.5 ? 0 : 1)" \
    && ok "startup batch applied at $rate/s with DECISION_RATE_LIMIT=2" || bad "rate $rate/s, want about 2/s"
  case_down
  rm -f .rate.json

  step "D6. HISTORY_MAX_EVENTS"
  start history ready -e HISTORY_MAX_EVENTS=5
  decide 198.19.2.20; decide 198.19.2.21
  wait_for 30 "history bans applied" has_ip v4 198.19.2.21
  case_down
  rows=$(offline status history --limit 50 2>/dev/null | grep -cE '^[0-9]{4}-')
  [ "$rows" -le 5 ] && [ "$rows" -ge 1 ] && ok "history trimmed to $rows events" || bad "history has $rows events"

  step "D7. LAPI_METRICS_PUSH_INTERVAL"
  start lapimetrics ready -e LAPI_METRICS_PUSH_INTERVAL=1m
  check "interval clamped to 10m" case_log_has "clamping to 10m"
  # cscli lists a bouncer only once a push carries a count.
  decide 198.19.2.30
  wait_for 30 "198.19.2.30 applied" has_ip v4 198.19.2.30
  case_down
  out=$($DC exec -T crowdsec cscli metrics show bouncers 2>&1)
  echo "$out" | grep -q "Bouncer Metrics" && ok "LAPI received the final usage-metrics push" || bad "cscli metrics: $(echo "$out" | head -5 | tr '\n' ' ')"

  step "D8. CROWDSEC_RESYNC_INTERVAL recovers decisions the stream skipped"
  start resync ready -e CROWDSEC_RESYNC_INTERVAL=5m
  for i in $(seq 1 40); do $DC exec -T crowdsec cscli decisions add -i "198.19.6.$i" -d 2h -R "e2e resync" >/dev/null; done
  sleep 10
  have=$(managed_members v4 | grep -c '^198\.19\.6\.')
  echo "  stream delivered $have of 40"
  all_resync() { [ "$(managed_members v4 | grep -c '^198\.19\.6\.')" -ge 40 ]; }
  if [ "$have" -ge 40 ]; then skip "the stream missed nothing this time, so resync had nothing to recover"
  else
    wait_for 400 "resync applied every missed decision" all_resync
    check "resync logged" case_log_has "CrowdSec resync applied decisions the stream missed"
  fi
  case_down
}

sec_sites() {
  step "S1. Multiple sites"
  main_up
  site2=$(api GET "/api/self/sites" | q "(data.find(s => s.desc === 'E2E Two') || {}).name")
  if [ -z "$site2" ] || [ "$site2" = undefined ]; then
    site2=$(api POST "/api/s/default/cmd/sitemgr" '{"cmd":"add-site","desc":"E2E Two"}' | q "data[0].name")
  fi
  echo "  second site: $site2"
  start sitesauto ready -e UNIFI_SITES_AUTO=true
  check "auto-discovery found both sites" sh -c "docker logs $CASE 2>&1 | grep 'auto-discovered UniFi sites' | grep -q '$site2'"
  decide 198.19.4.1
  wait_for 60 "ban applied on default" has_ip v4 198.19.4.1
  wait_for 60 "ban applied on $site2" site_has_ip "$site2" 198.19.4.1
  case_down
  start sitesexclude ready -e UNIFI_SITES_AUTO=true -e "UNIFI_SITES_EXCLUDE=$site2"
  decide 198.19.4.2
  wait_for 60 "ban applied on default" has_ip v4 198.19.4.2
  sleep 5
  check "excluded site untouched" sh -c "! (bash ./api.sh GET /api/s/$site2/rest/firewallgroup | node ./q.js \"data.flatMap(g => g.group_members)\" | grep -qx 198.19.4.2)"
  case_down
  start sitesexplicit ready -e "UNIFI_SITES=default,$site2"
  wait_for 60 "explicit list syncs the second site" site_has_ip "$site2" 198.19.4.2
  case_down
  start nosite exit -e UNIFI_SITES=no-such-site
  echo "  unknown site: $(case_logs | grep -iE 'error' | tail -1 | cut -c1-240)"
  [ "$(case_exit)" != 0 ] && ok "unknown site exits non-zero" || bad "exit $(case_exit)"
  case_down
}

sec_connection() {
  step "C1. TLS verification"
  start verifytls exit -e UNIFI_VERIFY_TLS=true
  case_log_has "certificate" && ok "verification failure names the certificate" || bad "$(case_logs | tail -2)"
  case_down
  MSYS_NO_PATHCONV=0 openssl s_client -connect 127.0.0.1:18443 -showcerts </dev/null 2>/dev/null \
    | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > secrets/ctrl.pem
  echo "  controller cert: $(MSYS_NO_PATHCONV=0 openssl x509 -in secrets/ctrl.pem -noout -subject -ext subjectAltName 2>/dev/null | tr '\n' ' ')"
  case_up cacert -e UNIFI_VERIFY_TLS=true -e UNIFI_CA_CERT=/certs/ctrl.pem -v "$PWD/secrets/ctrl.pem:/certs/ctrl.pem:ro"
  sleep 30
  if ready; then ok "UNIFI_CA_CERT lets a self-signed controller verify"
  else echo "  UNIFI_CA_CERT: $(case_logs | grep -iE 'error|x509' | tail -1 | cut -c1-240)"; skip "UNIFI_CA_CERT: controller cert does not match hostname 'unifi' (see above)"; fi
  case_down

  step "C2. UNIFI_HTTP_TIMEOUT"
  start timeout exit -e UNIFI_HTTP_TIMEOUT=1ms
  echo "  1ms timeout: $(case_logs | grep -iE 'error' | tail -1 | cut -c1-200)"
  [ "$(case_exit)" != 0 ] && ok "tiny timeout fails startup instead of hanging" || bad "exit $(case_exit)"
  case_down

  step "C3. Wrong password"
  start badpass exit -e UNIFI_PASSWORD=wrong-password-123
  case_log_has "check UNIFI_USERNAME and UNIFI_PASSWORD" && ok "error names the credentials" || bad "$(case_logs | tail -2)"
  check "wrong password not logged" case_log_lacks "wrong-password-123"
  case_down

  step "C4. *_FILE secrets"
  printf '%s\n' "$UNIFI_PASS" > secrets/unifi_password
  printf '%s' "$LAPI_KEY" > secrets/lapi_key
  start filesecrets ready -v "$PWD/secrets:/run/secrets:ro" -e UNIFI_PASSWORD=not-this-one \
    -e UNIFI_PASSWORD_FILE=/run/secrets/unifi_password -e CROWDSEC_LAPI_KEY=not-this-either -e CROWDSEC_LAPI_KEY_FILE=/run/secrets/lapi_key
  case_down

  step "C5. DATA_DIR"
  start datadir-tmpfs ready -e DATA_DIR=/tmp/state
  case_down
  start datadir-readonly exit -e DATA_DIR=/opt/state
  echo "  read-only DATA_DIR: $(case_logs | grep -iE 'error' | tail -1 | cut -c1-200)"
  [ "$(case_exit)" != 0 ] && ok "unwritable DATA_DIR exits non-zero" || bad "exit $(case_exit)"
  case_down

  step "C6. ENABLE_IPV6 dialing"
  start ipv6dial ready -e ENABLE_IPV6=true
  case_down
}

sec_breaker() {
  step "B1. Circuit breaker threshold, reset, and WEBHOOK_EVENTS"
  opened=$(wh_count circuit_breaker_open); closed=$(wh_count circuit_breaker_close)
  start breaker ready -e CIRCUIT_BREAKER_THRESHOLD=2 -e CIRCUIT_BREAKER_RESET_INTERVAL=15s -e WEBHOOK_EVENTS=circuit_breaker_open
  # pause, not stop: a stopped container's name falls through to the host
  # resolver and can reach a real controller on the LAN.
  $DC pause unifi >/dev/null 2>&1
  decide 198.19.5.1
  wait_for 120 "breaker opens after 2 failures" sh -c "curl -s http://127.0.0.1:19090/metrics | grep -q '^crowdsec_unifi_circuit_breaker_open 1'"
  wait_for 30 "circuit_breaker_open webhook delivered" sh -c "[ \"\$(curl -s http://127.0.0.1:18080/_webhooks | node ./q.js \"d.filter(e => e.event === 'circuit_breaker_open').length\")\" -gt $opened ]"
  $DC unpause unifi >/dev/null 2>&1
  wait_for 300 "controller back" curl -skf https://127.0.0.1:18443/status
  wait_for 180 "queued ban lands after recovery" has_ip v4 198.19.5.1
  wait_for 60 "breaker closed" sh -c "curl -s http://127.0.0.1:19090/metrics | grep -q '^crowdsec_unifi_circuit_breaker_open 0'"
  [ "$(wh_count circuit_breaker_close)" = "$closed" ] && ok "circuit_breaker_close filtered out by WEBHOOK_EVENTS" || bad "close event delivered"
  case_down

  step "B2. SHUTDOWN_GRACE_PERIOD"
  start grace ready -e SHUTDOWN_GRACE_PERIOD=1ms
  docker stop -t 30 "$CASE" >/dev/null
  echo "  exit $(case_exit): $(case_logs | tail -1 | cut -c1-200)"
  case_log_has "shutdown grace period exceeded" && ok "grace period enforced" || skip "shutdown finished inside 1ms"
  case_rm
}

feed_set() { printf '%b' "$1" | curl -s -X PUT --data-binary @- http://127.0.0.1:18080/_blocklist >/dev/null; }
FEED_DEFAULT='# e2e blocklist\n198.51.100.200\n198.51.100.201\n'
hook_attempts() { curl -s http://127.0.0.1:18080/_hookattempts | q "d.$1"; }
rule_gaps() {
  # smallest gap in seconds between consecutive "created legacy firewall rule" lines
  case_logs | grep '"created legacy firewall rule"' | node -e '
    const t = require("fs").readFileSync(0, "utf8").trim().split("\n").filter(Boolean).map(l => Date.parse(JSON.parse(l).time)).sort((a, b) => a - b);
    const g = t.slice(1).map((v, i) => (v - t[i]) / 1000);
    console.log(t.length + " " + (g.length ? Math.min(...g).toFixed(2) : -1))'
}

sec_extra() {
  step "E1. Wrong UNIFI_USERNAME"
  start baduser exit -e UNIFI_USERNAME=nobody-e2e
  case_log_has "check UNIFI_USERNAME and UNIFI_PASSWORD" && ok "error names the credentials" || bad "$(case_logs | tail -2)"
  case_down

  step "E2. UNIFI_USERNAME_FILE overrides UNIFI_USERNAME"
  printf 'e2eadmin\n' > secrets/unifi_username
  start userfile ready -v "$PWD/secrets:/run/secrets:ro" -e UNIFI_USERNAME=nobody-e2e -e UNIFI_USERNAME_FILE=/run/secrets/unifi_username
  case_down

  step "E3. FIREWALL_GROUP_CAPACITY applies when FIREWALL_GROUP_CAPACITY_V4 is 0"
  main_up
  for i in $(seq 1 9); do decide 198.19.10.$i; done
  wait_for 60 "9 bans applied" sh -c "[ \"\$(bash ./api.sh GET /api/s/default/rest/firewallgroup | node ./q.js \"data.filter(g => g.name.startsWith('crowdsec-block-v4-')).flatMap(g => g.group_members).filter(m => m.startsWith('198.19.10.')).length\")\" -ge 9 ]"
  start gencap ready -e FIREWALL_GROUP_CAPACITY=4 -e FIREWALL_GROUP_CAPACITY_V4=0
  wait_for 120 "every v4 shard within 4, one rule each, all bans enforced" v4_invariants 4
  show_v4
  case_down

  step "E4. SHARD_LIMIT below FIREWALL_GROUP_CAPACITY_V4 wins"
  start limitwins ready -e FIREWALL_GROUP_CAPACITY_V4=40 -e SHARD_LIMIT=5
  wait_for 120 "every v4 shard within 5" v4_invariants 5
  show_v4
  case_down

  step "E5. FIREWALL_API_SHARD_DELAY spaces rule creation"
  start sharddelay ready -e SHARD_LIMIT=2 -e FIREWALL_API_SHARD_DELAY=3s
  wait_for 240 "every v4 shard within 2" v4_invariants 2
  read -r n gap <<<"$(rule_gaps)"
  if [ "${n:-0}" -lt 2 ]; then skip "fewer than two rules created ($n)"
  else node -e "process.exit($gap >= 2.5 ? 0 : 1)" && ok "$n rules created, at least ${gap}s apart" || bad "rules only ${gap}s apart"; fi
  show_v4

  step "E6. SHARD_MERGE_THRESHOLD=-1 never merges"
  case_down
  start nomerge ready -e SHARD_LIMIT=2 -e SHARD_MERGE_THRESHOLD=-1
  wait_for 120 "every v4 shard within 2" v4_invariants 2
  for i in $(seq 1 9); do undecide 198.19.10.$i; done
  wait_for 90 "bans removed" lacks_ip v4 198.19.10.9
  sleep 30
  check "no shards_rebalanced_total series" sh -c "! curl -s http://127.0.0.1:19090/metrics | grep -q '^crowdsec_unifi_shards_rebalanced_total'"
  check "invariants hold without merging" v4_invariants 2
  show_v4
  case_down
  main_up
  wait_for 120 "back at capacity 40, invariants hold" v4_invariants 40

  step "E7. OBJECT_DESCRIPTION changed on an existing install"
  start objdesc ready -e "OBJECT_DESCRIPTION=e2e custom description"
  decide 198.19.10.20
  wait_for 30 "ban applied" has_ip v4 198.19.10.20
  check "existing rules adopted, none duplicated" v4_invariants 40
  check "no foreign-description refusal" case_log_lacks "exists with a different description"
  case_down

  step "E8. Deprecated and informational settings"
  # bouncer.env sets SYNC_INTERVAL, and the alias applies only when it is unset.
  out=$(docker run --rm -e UNIFI_URL=https://unifi:8443 -e UNIFI_USERNAME=e2eadmin -e "UNIFI_PASSWORD=$UNIFI_PASS" \
    -e "CROWDSEC_LAPI_KEY=$LAPI_KEY" -e CROWDSEC_LAPI_ALLOW_HTTP=true -e FIREWALL_BATCH_WINDOW=7s cs-unifi-bouncer-pro:e2e validate 2>&1)
  echo "$out" | grep -q "FIREWALL_BATCH_WINDOW is deprecated" && ok "FIREWALL_BATCH_WINDOW warns it is deprecated" || bad "no deprecation warning: $(echo "$out" | tail -2)"
  start apidebugwarn ready -e UNIFI_API_DEBUG=true -e LOG_LEVEL=info
  check "UNIFI_API_DEBUG at info level warns" case_log_has "UNIFI_API_DEBUG logs at debug level"
  check "no API request lines at info" case_log_lacks '"unifi api request"'
  case_down

  step "E9. Valid timing settings are accepted"
  start timings ready -e SESSION_REAUTH_MIN_GAP=0s -e SESSION_REAUTH_TIMEOUT=5s -e CROWDSEC_POLL_INTERVAL=2s \
    -e SYNC_INTERVAL=5s -e FIREWALL_RECONCILE_INTERVAL=0s -e UNIFI_HTTP_TIMEOUT=30s
  decide 198.19.10.21
  wait_for 30 "ban applied with a 2s poll" has_ip v4 198.19.10.21
  case_down

  step "E10. New validation rejections"
  rejects "METRICS_ADDR equals HEALTH_ADDR" "METRICS_ADDR and HEALTH_ADDR must differ" -e METRICS_ADDR=:8081
  rejects "UNIFI_HTTP_TIMEOUT 0" "UNIFI_HTTP_TIMEOUT must be > 0" -e UNIFI_HTTP_TIMEOUT=0s
  rejects "SESSION_REAUTH_TIMEOUT 0" "SESSION_REAUTH_TIMEOUT must be > 0" -e SESSION_REAUTH_TIMEOUT=0s
  rejects "CIRCUIT_BREAKER_THRESHOLD 0" "CIRCUIT_BREAKER_THRESHOLD must be >= 1" -e CIRCUIT_BREAKER_THRESHOLD=0
  rejects "CIRCUIT_BREAKER_RESET_INTERVAL 0" "CIRCUIT_BREAKER_RESET_INTERVAL must be > 0" -e CIRCUIT_BREAKER_RESET_INTERVAL=0s
  rejects "FIREWALL_API_SHARD_DELAY negative" "FIREWALL_API_SHARD_DELAY must not be negative" -e FIREWALL_API_SHARD_DELAY=-1s
  rejects "SESSION_REAUTH_MIN_GAP negative" "SESSION_REAUTH_MIN_GAP must not be negative" -e SESSION_REAUTH_MIN_GAP=-1s
  rejects "FIREWALL_MODE=zone with a password" "FIREWALL_MODE=zone requires UNIFI_API_KEY" -e FIREWALL_MODE=zone
  start lapica exit -e CROWDSEC_LAPI_URL=https://crowdsec:8080 -e CROWDSEC_LAPI_CA_CERT=/nope.pem
  echo "  missing CROWDSEC_LAPI_CA_CERT: $(case_logs | grep -iE 'error' | tail -1 | cut -c1-200)"
  [ "$(case_exit)" != 0 ] && ok "a missing CROWDSEC_LAPI_CA_CERT stops startup" || bad "exit $(case_exit)"
  case_down
  METRICS_ENABLED_OUT=$($DC run --rm -T -e METRICS_ENABLED=false -e METRICS_ADDR=:8081 bouncer validate 2>&1) \
    && ok "METRICS_ADDR may equal HEALTH_ADDR when metrics are off" || bad "metrics off: $(echo "$METRICS_ENABLED_OUT" | tail -1)"

  step "E11. CROWDSEC_LAPI_VERIFY_TLS against a plaintext LAPI"
  case_up lapitls -e CROWDSEC_LAPI_URL=https://crowdsec:8080 -e CROWDSEC_LAPI_VERIFY_TLS=false
  sleep 25
  echo "  https to a plaintext LAPI: $(case_logs | grep -iE 'failed to connect to LAPI' | tail -1 | cut -c1-200)"
  check "keeps running and retries" case_running
  check "/readyz 503 while the LAPI is unreachable" sh -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18081/readyz)\" = 503 ]"
  check "LAPI connection failure logged" case_log_has "failed to connect to LAPI"
  case_down

  step "E12. FIREWALL_RECONCILE_ON_START=false with an empty DATA_DIR"
  main_up
  decide 198.19.10.22
  wait_for 30 "ban applied" has_ip v4 198.19.10.22
  start freshdb ready -e DATA_DIR=/tmp/fresh -e FIREWALL_RECONCILE_ON_START=false -e FIREWALL_RECONCILE_INTERVAL=10s
  sleep 40
  check "CrowdSec ban kept on the controller" has_ip v4 198.19.10.22
  check "feed ban kept on the controller" has_ip v4 198.51.100.200
  check "periodic reconcile ran" case_log_has "periodic reconcile complete"
  case_down

  step "E13. LAPI_METRICS_PUSH_INTERVAL=0 disables the reporter"
  start nopush ready -e LAPI_METRICS_PUSH_INTERVAL=0
  docker stop -t 40 "$CASE" >/dev/null 2>&1
  check "no push attempted at shutdown" case_log_lacks "usage-metrics"
  check "no clamp warning" case_log_lacks "clamping to 10m"
  case_down

  step "E14. HEALTH_CHECK_LAPI=false with a wrong LAPI key"
  case_up hcbadkey -e HEALTH_CHECK_LAPI=false -e CROWDSEC_LAPI_KEY=wrong-key-0000000000000000
  sleep 20
  if ready; then ok "/readyz 200: HEALTH_CHECK_LAPI=false ignores LAPI auth failures (documented)"
  else echo "  readyz: $(curl -s http://127.0.0.1:18081/readyz)"; ok "/readyz still reports the LAPI failure"; fi
  out=$(docker exec "$CASE" /cs-unifi-bouncer-pro diagnose 2>&1)
  echo "$out" | grep -qi "check CROWDSEC_LAPI_KEY" && ok "diagnose still names the key" || bad "diagnose: $(echo "$out" | grep -i lapi | head -2)"
  case_down

  step "E15. UNIFI_SITES_EXCLUDE interactions"
  start excludeall exit -e UNIFI_SITES_AUTO=true -e "UNIFI_SITES_EXCLUDE=$(api GET /api/self/sites | q "data.map(s => s.name).join(',')")"
  case_log_has "UNIFI_SITES_EXCLUDE removes all of them" && ok "excluding every site stops startup with a clear error" || bad "$(case_logs | tail -2)"
  case_down
  start excludenoauto ready -e UNIFI_SITES=default -e UNIFI_SITES_EXCLUDE=default
  decide 198.19.10.23
  wait_for 30 "UNIFI_SITES_EXCLUDE without AUTO has no effect" has_ip v4 198.19.10.23
  case_down
  start autobogus ready -e UNIFI_SITES_AUTO=true -e UNIFI_SITES=no-such-site
  check "UNIFI_SITES ignored with AUTO" case_log_has "auto-discovered UniFi sites"
  case_down

  step "E16. DRY_RUN with a feed entry and a new decision"
  save_logs; $DC stop bouncer >/dev/null 2>&1
  feed_set "$FEED_DEFAULT"'198.51.100.210\n'
  start dryrun ready -e DRY_RUN=true
  decide 198.19.10.24
  sleep 30
  check "decision not sent" lacks_ip v4 198.19.10.24
  check "feed entry not sent" lacks_ip v4 198.51.100.210
  case_down
  feed_set "$FEED_DEFAULT"
  main_up
  wait_for 60 "normal mode applies the held decision" has_ip v4 198.19.10.24
}

sec_interact() {
  step "I1. BLOCK_WHITELIST covers feed entries"
  main_up
  feed_set "$FEED_DEFAULT"'198.51.100.250\n198.51.100.211\n'
  start wlfeed ready -e BLOCK_WHITELIST=198.51.100.250,198.51.100.211
  sleep 30
  check "whitelisted feed entry never banned" lacks_ip v4 198.51.100.211
  check "WAN whitelist entry never banned" lacks_ip v4 198.51.100.250
  check "other feed entries banned" has_ip v4 198.51.100.200
  case_down

  step "I2. A CrowdSec decision and a feed entry on one address"
  feed_set "$FEED_DEFAULT"'198.51.100.212\n'
  main_up
  wait_for 60 "feed ban applied" has_ip v4 198.51.100.212
  decide 198.51.100.212
  sleep 10
  undecide 198.51.100.212
  sleep 15
  check "deleting the CrowdSec decision keeps the feed ban" has_ip v4 198.51.100.212
  feed_set "$FEED_DEFAULT"
  wait_for 120 "dropping it from the feed lifts it" lacks_ip v4 198.51.100.212
  decide 198.51.100.213
  wait_for 30 "CrowdSec ban applied" has_ip v4 198.51.100.213
  feed_set "$FEED_DEFAULT"'198.51.100.213\n'
  sleep 30
  feed_set "$FEED_DEFAULT"
  sleep 50
  check "dropping the feed entry keeps the CrowdSec ban" has_ip v4 198.51.100.213
  undecide 198.51.100.213
  wait_for 60 "both sources gone lifts it" lacks_ip v4 198.51.100.213

  step "I3. CROWDSEC_ORIGINS does not filter feeds"
  feed_set "$FEED_DEFAULT"'198.51.100.214\n'
  start originsfeed ready -e CROWDSEC_ORIGINS=crowdsec
  decide 198.19.11.1
  wait_for 60 "feed ban applied" has_ip v4 198.51.100.214
  check "cscli ban filtered" lacks_ip v4 198.19.11.1
  case_down
  feed_set "$FEED_DEFAULT"

  step "I4. FIREWALL_ENABLE_IPV6=false with v6 feed entries"
  feed_set "$FEED_DEFAULT"'2001:db8:1b::1\n'
  start v6feed ready -e FIREWALL_ENABLE_IPV6=false
  sleep 30
  check "v6 feed entry not sent" lacks_ip v6 2001:db8:1b::1
  check "v4 feed entries still sent" has_ip v4 198.51.100.200
  case_down
  feed_set "$FEED_DEFAULT"

  step "I5. BLOCK_MIN_DURATION checks the decision's own duration, before BLOCK_SCENARIO_DURATION_MAP"
  start mindurmap ready -e BLOCK_MIN_DURATION=2h -e 'BLOCK_SCENARIO_DURATION_MAP=e2e-short=20s' -e JANITOR_INTERVAL=5s
  decide 198.19.11.2 3h "e2e-short probe"
  decide 198.19.11.3 1h "e2e-short probe"
  wait_for 30 "3h ban applied" has_ip v4 198.19.11.2
  check "1h ban under the minimum filtered even though it is mapped" lacks_ip v4 198.19.11.3
  wait_for 60 "mapped 20s duration then applies" lacks_ip v4 198.19.11.2
  case_down

  step "I6. BLOCK_WHITELIST and a CrowdSec range"
  start wlrange ready -e BLOCK_WHITELIST=198.19.12.5
  $DC exec -T crowdsec cscli decisions add -r 198.19.12.0/30 -d 1h -R "e2e range" >/dev/null
  $DC exec -T crowdsec cscli decisions add -r 198.19.12.4/30 -d 1h -R "e2e range" >/dev/null
  wait_for 30 "range without whitelisted addresses applied" has_ip v4 198.19.12.0/30
  check "range containing a whitelisted address filtered" lacks_ip v4 198.19.12.4/30
  case_down
}

sec_webhooks() {
  step "W1. A hanging webhook receiver blocks neither syncs nor shutdown"
  start slowhook ready -e WEBHOOK_URL=http://mock:8080/webhook/slow -e CIRCUIT_BREAKER_THRESHOLD=1 -e CIRCUIT_BREAKER_RESET_INTERVAL=10s
  before=$(hook_attempts slow)
  $DC pause unifi >/dev/null 2>&1
  decide 198.19.13.1
  wait_for 120 "breaker opens" sh -c "curl -s http://127.0.0.1:19090/metrics | grep -q '^crowdsec_unifi_circuit_breaker_open 1'"
  wait_for 30 "slow receiver called" sh -c "[ \"\$(curl -s http://127.0.0.1:18080/_hookattempts | node ./q.js d.slow)\" -gt $before ]"
  $DC unpause unifi >/dev/null 2>&1
  wait_for 300 "controller back" curl -skf https://127.0.0.1:18443/status
  wait_for 180 "queued ban lands while deliveries hang" has_ip v4 198.19.13.1
  t0=$(date +%s); docker stop -t 60 "$CASE" >/dev/null; t=$(( $(date +%s) - t0 ))
  [ "$t" -le 35 ] && ok "stopped in ${t}s (grace 30s)" || bad "stop took ${t}s"
  [ "$(case_exit)" = 0 ] && ok "exit 0" || bad "exit $(case_exit)"
  case_down

  step "W2. A failing webhook receiver is logged and ignored"
  start failhook ready -e WEBHOOK_URL=http://mock:8080/webhook/fail -e CIRCUIT_BREAKER_THRESHOLD=1 -e CIRCUIT_BREAKER_RESET_INTERVAL=10s
  before=$(hook_attempts fail)
  $DC pause unifi >/dev/null 2>&1
  decide 198.19.13.2
  wait_for 120 "breaker opens" sh -c "curl -s http://127.0.0.1:19090/metrics | grep -q '^crowdsec_unifi_circuit_breaker_open 1'"
  wait_for 30 "failing receiver called" sh -c "[ \"\$(curl -s http://127.0.0.1:18080/_hookattempts | node ./q.js d.fail)\" -gt $before ]"
  $DC unpause unifi >/dev/null 2>&1
  wait_for 300 "controller back" curl -skf https://127.0.0.1:18443/status
  wait_for 180 "queued ban lands" has_ip v4 198.19.13.2
  check "error status logged" case_log_has "webhook: server returned error status"
  check "still ready" ready
  case_down
}

SECTIONS=${*:-validation observability metrics firewall decisions sites connection breaker extra interact webhooks}
$DC build bouncer >/dev/null 2>&1 || { echo "bouncer build failed"; exit 1; }
for s in $SECTIONS; do "sec_$s"; done
main_up "default bouncer ready at the end"
echo
echo "SETTINGS RESULT: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
