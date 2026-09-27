#!/usr/bin/env bash
# Focused repro of step 11: controller outage with a ban queued during it.
# Needs the stack from run.sh (KEEP=1). Writes outage-bouncer.log.
set -u
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1
DC="docker compose --profile bouncer"
q() { node ./q.js "$1"; }
has_ip() { bash ./api.sh GET /api/s/default/rest/firewallgroup | q "data.some(g => g.name.startsWith('crowdsec-block-') && g.group_members.includes('$1'))" | grep -qx true; }
wait_ip() { for i in $(seq 1 "$2"); do has_ip "$1" && { echo "  $1 applied after ${i}s"; return 0; }; sleep 1; done; echo "  $1 NOT applied after $2s"; return 1; }

$DC up -d bouncer >/dev/null 2>&1
for i in $(seq 1 90); do [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18081/readyz)" = 200 ] && break; sleep 1; done
echo "bouncer ready"
$DC exec -T crowdsec cscli decisions add -i 203.0.113.20 -d 1h >/dev/null 2>&1
wait_ip 203.0.113.20 30

echo "stopping controller at $(date -u +%T)"
$DC stop unifi >/dev/null 2>&1
$DC exec -T crowdsec cscli decisions add -i 203.0.113.21 -d 1h >/dev/null 2>&1
sleep 10
echo "starting controller at $(date -u +%T)"
$DC start unifi >/dev/null 2>&1
for i in $(seq 1 300); do curl -skf -o /dev/null https://127.0.0.1:18443/status && break; sleep 1; done
echo "controller /status ok at $(date -u +%T)"
wait_ip 203.0.113.21 150
$DC logs bouncer --no-log-prefix > outage-bouncer.log 2>&1
docker exec csue2e-unifi-1 sh -c 'tail -n 300 /config/logs/server.log' > outage-unifi.log 2>&1
echo "logs: outage-bouncer.log outage-unifi.log"
