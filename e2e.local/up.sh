#!/usr/bin/env bash
# Start the stack with the bouncer and leave it running (for developing checks).
set -u
cd "$(dirname "$0")"
. ./lib.sh
docker info >/dev/null 2>&1 || { echo "Docker is not running"; exit 2; }
stack_up
$DC up -d --build bouncer >/dev/null 2>&1 || { echo "bouncer failed to start"; exit 1; }
wait_for 90 "bouncer /readyz 200" ready
