#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib-demo.sh
umask 077
mkdir -p .demo/tls
chmod 700 .demo .demo/tls
if [[ ! -f .demo/env ]]; then
  master_key="$(openssl rand -base64 32)"
  cat > .demo/env <<ENV
export DATABASE_URL='postgres://devctl:devctl-dev-only@127.0.0.1:54329/devctl?sslmode=disable'
export DEVCTL_MASTER_KEY='$master_key'
export DEVCTL_ISSUER='http://127.0.0.1:8081/realms/devctl'
export DEVCTL_DEV_HTTP=1
export DEVCTL_DEV_TOKEN_FILE=1
export DEVCTL_CONFIG_DIR='$PWD/.demo/client'
ENV
fi
# Keep the encryption key and database during upgrades. Rebuild this generated
# transport-settings file so earlier HTTP demos become HTTPS without key loss.
if [[ ! -f .demo/tls/server.crt ]] || ! openssl x509 -checkend 86400 -noout -in .demo/tls/server.crt >/dev/null; then
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 \
    -subj /CN=devctl-local-demo-CA -keyout .demo/tls/ca.key -out .demo/tls/ca.crt >/dev/null 2>&1
  openssl req -new -newkey rsa:2048 -nodes -sha256 -subj /CN=localhost \
    -keyout .demo/tls/server.key -out .demo/tls/server.csr >/dev/null 2>&1
  cat > .demo/tls/server.ext <<'EXT'
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EXT
  openssl x509 -req -sha256 -days 30 -in .demo/tls/server.csr \
    -CA .demo/tls/ca.crt -CAkey .demo/tls/ca.key -CAcreateserial \
    -extfile .demo/tls/server.ext -out .demo/tls/server.crt >/dev/null 2>&1
fi
cat > .demo/transport-env <<ENV
export DEVCTL_API='https://127.0.0.1:8080'
export DEVCTL_PUBLIC_URL='https://127.0.0.1:8080'
export DEVCTL_TLS_CERT='$PWD/.demo/tls/server.crt'
export DEVCTL_TLS_KEY='$PWD/.demo/tls/server.key'
export DEVCTL_GATEWAY_CA_FILE='$PWD/.demo/tls/ca.crt'
export DEVCTL_API_CA_FILE='$PWD/.demo/tls/ca.crt'
ENV
if ! grep -q '^source .*transport-env' .demo/env; then
  printf '\nsource '\''%s/.demo/transport-env'\''\n' "$PWD" >>.demo/env
fi
docker --host=unix:///var/run/docker.sock compose -f compose.yaml up -d --build --wait postgres keycloak
ready=0
for attempt in {1..120}; do
  if curl --max-time 2 -fsS http://127.0.0.1:8081/realms/devctl/.well-known/openid-configuration >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then echo 'Keycloak failed readiness; inspect docker compose logs keycloak' >&2; exit 1; fi
if [[ -f .demo/backend.pid ]]; then
  backend_pid="$(cat .demo/backend.pid)"
  if devctl_demo_owns_backend "$backend_pid"; then
    kill "$backend_pid"
    for attempt in {1..50}; do
      if ! kill -0 "$backend_pid" 2>/dev/null; then break; fi
      sleep 0.1
    done
  fi
  rm .demo/backend.pid
fi
# Detect a listener rather than issuing an HTTP request to an unknown service.
if (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null; then echo 'Port 8080 is already in use; refusing to replace the service.' >&2; exit 1; fi
source .demo/env
backend_launcher=()
if command -v setsid >/dev/null 2>&1; then backend_launcher=(setsid); fi
nohup "${backend_launcher[@]}" ./bin/devctld >.demo/backend.log 2>&1 </dev/null &
echo "$!" > .demo/backend.pid
for attempt in {1..30}; do
  if curl --max-time 2 --cacert "$DEVCTL_GATEWAY_CA_FILE" -fsS "$DEVCTL_API/readyz" >/dev/null 2>&1; then
    echo 'HTTPS demo ready. Run: source .demo/env; export PATH="$PWD/bin:$PATH"; devctl login'
    echo 'For all new shells: devctl shell install --shell bash (or zsh/fish).'
    echo 'Development accounts: alice / alice-dev-only, bob / bob-dev-only, admin / admin-dev-only'
    echo 'Existing registrations are preserved; no Kubernetes cluster is contacted by startup.'
    exit 0
  fi
  sleep 1
done
echo 'Backend failed readiness; inspect .demo/backend.log' >&2
exit 1
