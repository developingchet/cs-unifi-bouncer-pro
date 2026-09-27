#!/usr/bin/env bash
# api.sh <METHOD> <path> [json-body]: call the controller with the admin session.
# Logs in first when the session cookie is missing or rejected.
set -u
U=${UNIFI_HOST_URL:-https://127.0.0.1:18443}
JAR=$(dirname "$0")/.cookies
login() {
  curl -sk -c "$JAR" -o /dev/null -H 'Content-Type: application/json' -X POST "$U/api/login" \
    -d '{"username":"e2eadmin","password":"E2e-Admin-Pass-123"}'
}
call() {
  curl -sk -b "$JAR" -w '\n%{http_code}' -H 'Content-Type: application/json' -X "$1" "$U$2" ${3:+-d "$3"}
}
[ -f "$JAR" ] || login
out=$(call "$@")
if [ "$(echo "$out" | tail -1)" = 401 ]; then login; out=$(call "$@"); fi
echo "$out" | sed '$d'
