#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib-demo.sh
if [[ -f .demo/backend.pid ]]; then
  backend_pid="$(cat .demo/backend.pid)"
  if devctl_demo_owns_backend "$backend_pid"; then
    kill "$backend_pid"
  fi
  rm -f .demo/backend.pid
fi
docker --host=unix:///var/run/docker.sock compose -f compose.yaml down --volumes
# This directory holds only this demo's login copies, encryption key and logs.
rm -rf .demo
