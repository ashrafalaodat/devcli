#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export DEVCTL_TEST_DATABASE_URL="${DEVCTL_TEST_DATABASE_URL:-postgres://devctl:devctl-dev-only@127.0.0.1:54329/devctl?sslmode=disable}"
export DEVCTL_TEST_ISSUER="${DEVCTL_TEST_ISSUER:-http://127.0.0.1:8081/realms/devctl}"
go test -race ./internal/... -count=1
go test -race ./tests/integration -count=1 -v
