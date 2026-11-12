#!/usr/bin/env bash
# Check that password migration cannot execute against an unrelated container.
# Docker is a local test double: this script makes no Docker or network call.
set -euo pipefail
set +x
cd "$(dirname "$0")/.."
umask 077
test_root="$(mktemp -d "${TMPDIR:-/tmp}/devctl-password-guards.XXXXXXXX")"
trap 'rm -rf -- "$test_root"' EXIT
mkdir -p "$test_root/bin"
export DEVCTL_PASSWORD_GUARD_LOG="$test_root/calls"
export DEVCTL_PASSWORD_GUARD_CASE=valid
export DEVCTL_PASSWORD_GUARD_STAGE="$test_root"
cat >"$test_root/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
set -euo pipefail
for option in DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH; do
  if [[ -v "$option" ]]; then echo 'Inherited Docker selector was not cleared.' >&2; exit 99; fi
done
printf '%s\n' "$*" >>"$DEVCTL_PASSWORD_GUARD_LOG"
[[ "$1" == --host=unix:///var/run/docker.sock ]] || exit 99
shift
case "$1" in
  compose)
    [[ "$DEVCTL_PASSWORD_GUARD_CASE" == missing ]] || printf '%064d\n' 1
    ;;
  inspect)
    case "$DEVCTL_PASSWORD_GUARD_CASE" in
      foreign) echo 'company|keycloak|/company-keycloak-1|devctl-keycloak:26.5.2-demo|true' ;;
      image) echo 'devctl-demo|keycloak|/devctl-demo-keycloak-1|company-keycloak:latest|true' ;;
      stopped) echo 'devctl-demo|keycloak|/devctl-demo-keycloak-1|devctl-keycloak:26.5.2-demo|false' ;;
      *) echo 'devctl-demo|keycloak|/devctl-demo-keycloak-1|devctl-keycloak:26.5.2-demo|true' ;;
    esac
    ;;
  port)
    if [[ "$DEVCTL_PASSWORD_GUARD_CASE" == external ]]; then echo '0.0.0.0:8081'; else echo '127.0.0.1:8081'; fi
    ;;
  exec)
    # Execute the real heredoc against private filesystem/tool stand-ins. No
    # container, identity-provider connection or real credential is involved.
    cat >"$DEVCTL_PASSWORD_GUARD_STAGE/container-input"
    python3 - "$DEVCTL_PASSWORD_GUARD_STAGE" <<'PY'
import pathlib,sys
root=pathlib.Path(sys.argv[1])
source=(root/'container-input').read_text()
source=source.replace('/opt/keycloak/bin/kcadm.sh', str(root/'kcadm'))
source=source.replace('/opt/keycloak/data/h2/.devctl-demo-passwords-v1', str(root/'migration-marker'))
(root/'container-run').write_text(source)
PY
    # docker exec options precede the fixed container command; its final
    # argument is the migration mode passed through to bash -s.
    KC_BOOTSTRAP_ADMIN_USERNAME=bootstrap-admin KC_BOOTSTRAP_ADMIN_PASSWORD=fixture-only \
      /bin/bash "$DEVCTL_PASSWORD_GUARD_STAGE/container-run" "${@: -1}"
    ;;
  *) exit 99 ;;
esac
DOCKER
chmod +x "$test_root/bin/docker"

cat >"$test_root/kcadm" <<'KCADM'
#!/usr/bin/env bash
set -euo pipefail
alice_id=11111111-1111-4111-8111-111111111111
admin_id=22222222-2222-4222-8222-222222222222
if [[ "$1" == config ]]; then
  [[ "$*" == *'--server http://127.0.0.1:8080 --realm master'* ]] || exit 99
  echo login >>"$DEVCTL_PASSWORD_GUARD_STAGE/admin-calls"
elif [[ "$1" == set-password ]]; then
  case "$*" in
    *"--userid $alice_id --new-password alice"*) echo alice >>"$DEVCTL_PASSWORD_GUARD_STAGE/password-resets" ;;
    *"--userid $admin_id --new-password admin"*) echo admin >>"$DEVCTL_PASSWORD_GUARD_STAGE/password-resets" ;;
    *) echo 'Unexpected account/password was reset.' >&2; exit 99 ;;
  esac
elif [[ "$1" == get && "$2" == users ]]; then
  if [[ "$*" == *username=alice* ]]; then echo "$alice_id,alice";
  elif [[ "$*" == *username=admin* ]]; then echo "$admin_id,admin";
  else exit 99; fi
elif [[ "$1" == get && "$2" == users/*/groups ]]; then
  echo '[{"id":"group-id","path":"/existing-group"}]'
elif [[ "$1" == get && "$2" == "users/$alice_id" ]]; then
  echo '{"id":"11111111-1111-4111-8111-111111111111","username":"alice","email":"alice@example.test","enabled":true}'
elif [[ "$1" == get && "$2" == "users/$admin_id" ]]; then
  echo '{"id":"22222222-2222-4222-8222-222222222222","username":"admin","email":"admin@example.test","enabled":true}'
else exit 99; fi
KCADM
chmod +x "$test_root/kcadm"

for test_case in missing foreign image stopped external; do
  export DEVCTL_PASSWORD_GUARD_CASE="$test_case"
  : >"$DEVCTL_PASSWORD_GUARD_LOG"
  if PATH="$test_root/bin:$PATH" DOCKER_HOST=tcp://unapproved.invalid:2375 DOCKER_CONTEXT=foreign \
    ./scripts/update-demo-passwords.sh --reset >"$test_root/output" 2>&1; then
    echo "Password guard accepted unsafe fixture: $test_case" >&2
    exit 1
  fi
  if rg -q -- '--host=unix:///var/run/docker.sock exec' "$DEVCTL_PASSWORD_GUARD_LOG"; then
    echo "Password guard executed unsafe fixture: $test_case" >&2
    exit 1
  fi
done

export DEVCTL_PASSWORD_GUARD_CASE=valid
: >"$DEVCTL_PASSWORD_GUARD_LOG"
PATH="$test_root/bin:$PATH" DOCKER_HOST=tcp://unapproved.invalid:2375 DOCKER_CONTEXT=foreign \
  ./scripts/update-demo-passwords.sh --if-needed >"$test_root/output" 2>&1
rg -q -- '--host=unix:///var/run/docker.sock exec' "$DEVCTL_PASSWORD_GUARD_LOG"
[[ "$(cat "$test_root/password-resets")" == $'alice\nadmin' ]]
[[ "$(stat -c '%a' "$test_root/migration-marker")" == 600 ]]
cp "$test_root/password-resets" "$test_root/resets-before-repeat"
cp "$test_root/admin-calls" "$test_root/admin-before-repeat"
PATH="$test_root/bin:$PATH" ./scripts/update-demo-passwords.sh --if-needed >"$test_root/output" 2>&1
cmp -s "$test_root/password-resets" "$test_root/resets-before-repeat"
cmp -s "$test_root/admin-calls" "$test_root/admin-before-repeat"
PATH="$test_root/bin:$PATH" ./scripts/update-demo-passwords.sh --reset >"$test_root/output" 2>&1
[[ "$(cat "$test_root/password-resets")" == $'alice\nadmin\nalice\nadmin' ]]
printf '%s\n' 'Local demo password ownership/loopback guards, preserved identities and one-time migration passed without Docker or network access.'
