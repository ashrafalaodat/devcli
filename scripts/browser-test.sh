#!/usr/bin/env bash
# Run the browser SSO/PAT integration test against a disposable local IdP.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
export TMPDIR="${TMPDIR:-$PWD/.demo/test-tmp}"
mkdir -p "$TMPDIR"
browser_test_stage="$(mktemp -d "$TMPDIR/devctl-browser-test.XXXXXX")"
browser_test_container=""
browser_test_cleanup() {
  if [[ -n "$browser_test_container" ]]; then
    docker --host=unix:///var/run/docker.sock rm -f "$browser_test_container" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$browser_test_stage"
}
trap browser_test_cleanup EXIT
python3 - "$browser_test_stage/realm.json" <<'PY'
import json,sys
with open('deploy/keycloak-realm.json') as f: realm=json.load(f)
for client in realm['clients']:
    if client['clientId']=='devctl-web':
        client['redirectUris']=['https://127.0.0.1:19090/auth/callback']
with open(sys.argv[1],'w') as f: json.dump(realm,f)
PY
chmod 644 "$browser_test_stage/realm.json"
browser_test_container="$(docker --host=unix:///var/run/docker.sock run -d \
  --label devctl.test=browser-sso \
  -p 127.0.0.1:18081:8080 \
  -e KC_HOSTNAME=http://127.0.0.1:18081 \
  --mount "type=bind,src=$browser_test_stage/realm.json,dst=/opt/keycloak/data/import/devctl-realm.json,readonly" \
  devctl-keycloak:26.5.2-demo start-dev --import-realm)"
browser_test_ready=0
for attempt in {1..90}; do
  if curl -fsS --max-time 2 http://127.0.0.1:18081/realms/devctl/.well-known/openid-configuration >/dev/null 2>&1; then browser_test_ready=1;break;fi
  if [[ "$(docker --host=unix:///var/run/docker.sock inspect --format '{{.State.Running}}' "$browser_test_container")" != true ]]; then break;fi
  sleep 1
done
if [[ "$browser_test_ready" != 1 ]]; then
  echo 'Disposable browser test IdP failed readiness.' >&2
  docker --host=unix:///var/run/docker.sock logs --tail 50 "$browser_test_container" >&2
  exit 1
fi
export DEVCTL_TEST_DATABASE_URL="${DEVCTL_TEST_DATABASE_URL:-postgres://devctl:devctl-dev-only@127.0.0.1:54329/devctl?sslmode=disable}"
export DEVCTL_TEST_ISSUER=http://127.0.0.1:18081/realms/devctl
export DEVCTL_TEST_WEB_URL=https://127.0.0.1:19090
go test -race ./tests/integration -run '^TestBrowserAccess$' -count=1 -v
