#!/usr/bin/env bash
# Run lib.sh helpers against a running stack: bash e2e.local/try.sh 'rejects "x" "y" -e K=V'
set -u
cd "$(dirname "$0")"
. ./lib.sh
eval "$1"
