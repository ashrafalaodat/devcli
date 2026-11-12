#!/usr/bin/env bash
# Update only the two public development passwords in the owned local demo.
# Application login continues to use Authorization Code/PKCE; this is a local
# Keycloak administration operation, never a developer password-grant flow.
set -euo pipefail
set +x
cd "$(dirname "$0")/.."

mode="${1:---if-needed}"
if [[ "$#" -gt 1 || ( "$mode" != --if-needed && "$mode" != --reset ) ]]; then
  echo 'Usage: ./scripts/update-demo-passwords.sh [--if-needed|--reset]' >&2
  exit 2
fi

docker_cmd=(env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS \
  -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock)
container="$("${docker_cmd[@]}" compose -f compose.yaml ps --all --quiet keycloak)"
if [[ ! "$container" =~ ^[a-f0-9]{64}$ ]]; then
  echo 'Start this project’s local demo Keycloak before updating its demo passwords.' >&2
  exit 1
fi
identity="$("${docker_cmd[@]}" inspect --format '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{.Name}}|{{.Config.Image}}|{{.State.Running}}' "$container")"
if [[ "$identity" != 'devctl-demo|keycloak|/devctl-demo-keycloak-1|devctl-keycloak:26.5.2-demo|true' ]]; then
  echo 'Refusing to change credentials outside the running devctl-demo Keycloak container.' >&2
  exit 1
fi
if [[ "$("${docker_cmd[@]}" port "$container" 8080/tcp)" != '127.0.0.1:8081' ]]; then
  echo 'Refusing to change credentials: the demo Keycloak listener is not the expected loopback endpoint.' >&2
  exit 1
fi

"${docker_cmd[@]}" exec -i "$container" /bin/bash -s -- "$mode" <<'KEYCLOAK'
set -euo pipefail
set +x
umask 077
mode="$1"
marker=/opt/keycloak/data/h2/.devctl-demo-passwords-v1
if [[ "$mode" == --if-needed && -f "$marker" && "$(cat "$marker")" == v1 ]]; then
  echo 'Local demo Alice/admin password update already applied.'
  exit 0
fi
if [[ "${KC_BOOTSTRAP_ADMIN_USERNAME:-}" != bootstrap-admin || -z "${KC_BOOTSTRAP_ADMIN_PASSWORD:-}" ]]; then
  echo 'The local demo bootstrap administrator is unavailable; no user credentials were changed.' >&2
  exit 1
fi
cli_config="$(mktemp /tmp/devctl-demo-passwords.XXXXXX)"
marker_tmp="${marker}.$$"
trap 'rm -f -- "$cli_config" "$marker_tmp"' EXIT
kc() { /opt/keycloak/bin/kcadm.sh "$@" --config "$cli_config"; }
if ! kc config credentials --server http://127.0.0.1:8080 --realm master \
  --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null 2>&1; then
  echo 'Local demo Keycloak administration login failed; no user credentials were changed.' >&2
  exit 1
fi

user_id() {
  local name="$1" record id username
  if ! record="$(kc get users -r devctl -q "username=$name" -q exact=true --fields id,username --format csv --noquotes 2>/dev/null)"; then
    echo 'Could not read the existing local demo account; no replacement user will be created.' >&2
    return 1
  fi
  IFS=, read -r id username <<<"$record"
  if [[ "$record" == *$'\n'* || ! "$id" =~ ^[a-fA-F0-9-]{36}$ || "$username" != "$name" ]]; then
    echo 'Expected exactly one existing local demo account; refusing to recreate or replace users.' >&2
    return 1
  fi
  printf '%s' "$id"
}
snapshot() {
  kc get "users/$1" -r devctl --fields id,username,email,enabled 2>/dev/null || { echo 'Could not read local demo identity metadata.' >&2; return 1; }
  kc get "users/$1/groups" -r devctl --fields id,path 2>/dev/null || { echo 'Could not read local demo group metadata.' >&2; return 1; }
}
alice_id="$(user_id alice)"
admin_id="$(user_id admin)"
alice_before="$(snapshot "$alice_id")"
admin_before="$(snapshot "$admin_id")"
if ! kc set-password -r devctl --userid "$alice_id" --new-password alice >/dev/null 2>&1; then
  echo 'Could not update the local Alice password; existing users were retained.' >&2
  exit 1
fi
if ! kc set-password -r devctl --userid "$admin_id" --new-password admin >/dev/null 2>&1; then
  echo 'Alice was updated, but the local admin password update failed. Rerun this script safely.' >&2
  exit 1
fi
if [[ "$(user_id alice)" != "$alice_id" || "$(user_id admin)" != "$admin_id" ||
  "$(snapshot "$alice_id")" != "$alice_before" || "$(snapshot "$admin_id")" != "$admin_before" ]]; then
  echo 'Local demo user identity/group verification failed; existing users were not recreated.' >&2
  exit 1
fi
printf '%s\n' v1 >"$marker_tmp"
chmod 600 "$marker_tmp"
mv "$marker_tmp" "$marker"
echo 'Local demo passwords updated: alice / alice and admin / admin. User IDs and groups were preserved.'
KEYCLOAK
