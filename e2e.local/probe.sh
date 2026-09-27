#!/usr/bin/env bash
# probe.sh <path>...: GET each path with the admin session, print code + body head.
U=https://127.0.0.1:18443
JAR=$(dirname "$0")/.cookies
CSRF=$(grep -i csrf_token "$JAR" 2>/dev/null | awk '{print $7}')
for p in "$@"; do
  out=$(curl -sk -b "$JAR" -H "X-Csrf-Token: $CSRF" ${APIKEY:+-H "X-API-KEY: $APIKEY"} -w '\n%{http_code}' "$U$p")
  code=$(echo "$out" | tail -1)
  echo "[$code] $p :: $(echo "$out" | sed '$d' | head -c 400)"
done
