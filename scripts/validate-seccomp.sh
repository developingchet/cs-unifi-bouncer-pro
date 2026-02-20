#!/usr/bin/env bash
# validate-seccomp.sh — static validation for a seccomp profile JSON.
# Usage: bash scripts/validate-seccomp.sh [path-to-profile]
set -euo pipefail

PROFILE="${1:-security/seccomp-unifi.json}"

echo "Validating seccomp profile: $PROFILE"

# Check the file exists
if [ ! -f "$PROFILE" ]; then
  echo "ERROR: File not found: $PROFILE"
  exit 1
fi

# Validate JSON syntax
if ! jq empty "$PROFILE" 2>/dev/null; then
  echo "ERROR: Invalid JSON in $PROFILE"
  exit 1
fi

# Check required top-level keys
for key in defaultAction syscalls; do
  if ! jq -e "has(\"$key\")" "$PROFILE" > /dev/null; then
    echo "ERROR: Missing required key: $key"
    exit 1
  fi
done

# Verify the default action is a deny (not an allow-all)
DEFAULT_ACTION=$(jq -r '.defaultAction' "$PROFILE")
if [ "$DEFAULT_ACTION" = "SCMP_ACT_ALLOW" ]; then
  echo "ERROR: defaultAction is SCMP_ACT_ALLOW — profile is not an allowlist."
  exit 1
fi

# Verify critical syscalls are present in the allowlist
REQUIRED_SYSCALLS=(
  "read" "write" "close" "fstat" "mmap" "munmap"
  "rt_sigaction" "rt_sigprocmask" "rt_sigreturn"
  "futex" "nanosleep" "clock_nanosleep"
  "socket" "connect" "sendto" "recvfrom"
  "openat" "getdents64" "execve" "exit_group"
)

ALLOWLIST=$(jq -r '.syscalls[] | select(.action == "SCMP_ACT_ALLOW") | .names[]' "$PROFILE" 2>/dev/null || true)

MISSING=()
for syscall in "${REQUIRED_SYSCALLS[@]}"; do
  if ! echo "$ALLOWLIST" | grep -qx "$syscall"; then
    MISSING+=("$syscall")
  fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
  echo "WARNING: These commonly required syscalls are not in the allowlist:"
  for s in "${MISSING[@]}"; do
    echo "  - $s"
  done
  echo "(This may be intentional for a minimal profile — review before merging)"
fi

COUNT=$(jq '[.syscalls[] | select(.action == "SCMP_ACT_ALLOW") | .names | length] | add // 0' "$PROFILE")
echo "OK: Profile valid — $COUNT syscall entries in allowlist (defaultAction: $DEFAULT_ACTION)"
