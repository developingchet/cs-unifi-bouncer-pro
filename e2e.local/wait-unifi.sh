#!/usr/bin/env bash
# wait-unifi.sh: block until the controller answers /status (max ~5 min).
for _ in $(seq 1 60); do
  c=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:18443/status)
  [ "$c" = 200 ] && break
  sleep 5
done
echo "status_code=$c"
curl -sk https://127.0.0.1:18443/status
echo
