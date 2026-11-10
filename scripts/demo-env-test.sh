#!/usr/bin/env bash
set -euo pipefail

# Exercise generated demo configuration without Docker, Kubernetes, or a server.
# Never trace these checks: the environment includes the database encryption key.
set +x
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib-demo.sh"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/devctl-demo-env.XXXXXXXX")"
trap 'rm -rf -- "$test_root"' EXIT
umask 077

fail() {
  printf 'Demo environment regression failed: %s\n' "$1" >&2
  exit 1
}

prepare() {
  (cd -- "$1" && devctl_demo_prepare_env) || fail 'environment preparation'
}

read_key() {
  (source "$1/.demo/env" && printf '%s' "$DEVCTL_MASTER_KEY")
}

check_environment() {
  local repo_path="$1" expected_key="$2" expected_custom="${3:-}"
  # The saved environment must work from any working directory and must not rely
  # on configuration inherited from the caller's shell.
  (
    cd -- "$test_root/unrelated" || exit 1
    unset DEVCTL_API DEVCTL_PUBLIC_URL DEVCTL_LISTEN DEVCTL_CONFIG_DIR
    unset DEVCTL_TLS_CERT DEVCTL_TLS_KEY DEVCTL_GATEWAY_CA_FILE DEVCTL_API_CA_FILE
    unset DEVCTL_MASTER_KEY DEVCTL_DEMO_TEST_CUSTOM
    source "$repo_path/.demo/env" || exit 1
    [[ "$DEVCTL_MASTER_KEY" == "$expected_key" &&
      "$DEVCTL_LISTEN" == '127.0.0.1:9090' &&
      "$DEVCTL_API" == 'https://127.0.0.1:9090' &&
      "$DEVCTL_PUBLIC_URL" == 'https://127.0.0.1:9090' &&
      "$DEVCTL_CONFIG_DIR" == "$repo_path/.demo/client" &&
      "$DEVCTL_TLS_CERT" == "$repo_path/.demo/tls/server.crt" &&
      "$DEVCTL_TLS_KEY" == "$repo_path/.demo/tls/server.key" &&
      "$DEVCTL_GATEWAY_CA_FILE" == "$repo_path/.demo/tls/ca.crt" &&
      "$DEVCTL_API_CA_FILE" == "$repo_path/.demo/tls/ca.crt" &&
      "${DEVCTL_DEMO_TEST_CUSTOM:-}" == "$expected_custom" ]]
  ) || fail 'generated values or preserved key/custom setting'
  [[ "$(stat -c '%a' -- "$repo_path/.demo/env")" == 600 ]] || fail 'env permissions'
  [[ "$(stat -c '%a' -- "$repo_path/.demo/transport-env")" == 600 ]] || fail 'transport-env permissions'
}

mkdir -p -- "$test_root/unrelated"
original_repo="$test_root/before's checkout"
moved_repo="$test_root/after's checkout"
mkdir -p -- "$original_repo/.demo"
prepare "$original_repo"
fresh_key="$(read_key "$original_repo")"
[[ -n "$fresh_key" ]] || fail 'fresh encryption key missing'
check_environment "$original_repo" "$fresh_key"
printf '%s\n' "export DEVCTL_DEMO_TEST_CUSTOM='preserve-me'" >>"$original_repo/.demo/env"

mv -- "$original_repo" "$moved_repo"
prepare "$moved_repo"
check_environment "$moved_repo" "$fresh_key" 'preserve-me'
if grep -Fq -- "$original_repo" "$moved_repo/.demo/env" "$moved_repo/.demo/transport-env"; then
  fail 'old checkout path remains after relocation'
fi
cp -- "$moved_repo/.demo/env" "$test_root/env-before-repeat"
cp -- "$moved_repo/.demo/transport-env" "$test_root/transport-before-repeat"
prepare "$moved_repo"
cmp -s -- "$moved_repo/.demo/env" "$test_root/env-before-repeat" || fail 'env changed on repeated preparation'
cmp -s -- "$moved_repo/.demo/transport-env" "$test_root/transport-before-repeat" || fail 'transport-env changed on repeated preparation'

# Reproduce the previous format after its original checkout has been removed.
legacy_repo="$test_root/legacy's moved checkout"
removed_repo="$test_root/removed-checkout"
mkdir -p -- "$legacy_repo/.demo"
legacy_key="$(openssl rand -base64 32)"
{
  printf 'export DEVCTL_MASTER_KEY=%q\n' "$legacy_key"
  printf '%s\n' "export DATABASE_URL='postgres://devctl:devctl-dev-only@127.0.0.1:54329/devctl?sslmode=disable'"
  printf '%s\n' "export DEVCTL_DEMO_TEST_CUSTOM='legacy-preserved'"
  printf 'export DEVCTL_CONFIG_DIR=%q\n' "$removed_repo/.demo/client"
  printf 'source %q\n' "$removed_repo/.demo/transport-env"
} >"$legacy_repo/.demo/env"
chmod 644 -- "$legacy_repo/.demo/env"
prepare "$legacy_repo"
check_environment "$legacy_repo" "$legacy_key" 'legacy-preserved'
if grep -Fq -- "$removed_repo" "$legacy_repo/.demo/env" "$legacy_repo/.demo/transport-env"; then
  fail 'legacy checkout path remains after migration'
fi
printf '%s\n' 'Demo environment relocation regression passed.'
