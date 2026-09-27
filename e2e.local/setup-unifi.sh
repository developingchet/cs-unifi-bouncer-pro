#!/usr/bin/env bash
# setup-unifi.sh: complete the first-run wizard headlessly and log in.
# A freshly booted controller answers /status before it can persist the admin,
# so the wizard calls are repeated until a login succeeds.
set -u
U=https://127.0.0.1:18443
ADMIN_USER=${ADMIN_USER:-e2eadmin}
ADMIN_PASS=${ADMIN_PASS:-E2e-Admin-Pass-123}
JAR=${JAR:-$(dirname "$0")/.cookies}
post() { curl -sk -b "$JAR" -c "$JAR" -H 'Content-Type: application/json' -X POST "$U$1" -d "$2"; }

for attempt in $(seq 1 30); do
  post /api/cmd/sitemgr "{\"cmd\":\"add-default-admin\",\"name\":\"$ADMIN_USER\",\"email\":\"e2e@example.invalid\",\"x_password\":\"$ADMIN_PASS\"}" >/dev/null
  post /api/cmd/system '{"cmd":"set-installed"}' >/dev/null
  if post /api/login "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | grep -q '"rc":"ok"'; then
    echo "controller ready after $attempt attempt(s)"
    exit 0
  fi
  sleep 5
done
echo "controller setup did not complete" >&2
exit 1
