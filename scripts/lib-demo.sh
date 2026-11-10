#!/usr/bin/env bash
# Sourced from the repository root. Never signal an unrelated process based on a
# stale PID alone. NFS keeps running replaced binaries under a .nfs filename.
devctl_demo_prepare_env() {
  local master_key demo_env_tmp demo_transport_tmp demo_line
  mkdir -p .demo
  chmod 700 .demo
  if [[ ! -f .demo/env ]]; then
    master_key="$(openssl rand -base64 32)"
    cat > .demo/env <<ENV
export DATABASE_URL='postgres://devctl:devctl-dev-only@127.0.0.1:54329/devctl?sslmode=disable'
export DEVCTL_MASTER_KEY='$master_key'
export DEVCTL_ISSUER='http://127.0.0.1:8081/realms/devctl'
export DEVCTL_DEV_HTTP=1
export DEVCTL_DEV_TOKEN_FILE=1
ENV
  fi

  # Refresh generated paths after a move, preserving the encryption key and
  # other saved settings. Shell-quote paths so spaces and apostrophes are safe.
  demo_transport_tmp="$(mktemp .demo/transport-env.XXXXXX)"
  printf 'export %s=%q\n' \
    DEVCTL_LISTEN '127.0.0.1:9090' \
    DEVCTL_API 'https://127.0.0.1:9090' \
    DEVCTL_PUBLIC_URL 'https://127.0.0.1:9090' \
    DEVCTL_CONFIG_DIR "$PWD/.demo/client" \
    DEVCTL_TLS_CERT "$PWD/.demo/tls/server.crt" \
    DEVCTL_TLS_KEY "$PWD/.demo/tls/server.key" \
    DEVCTL_GATEWAY_CA_FILE "$PWD/.demo/tls/ca.crt" \
    DEVCTL_API_CA_FILE "$PWD/.demo/tls/ca.crt" >"$demo_transport_tmp"
  chmod 600 "$demo_transport_tmp"
  mv "$demo_transport_tmp" .demo/transport-env

  demo_env_tmp="$(mktemp .demo/env.XXXXXX)"
  while IFS= read -r demo_line || [[ -n "$demo_line" ]]; do
    case "$demo_line" in
      'export DEVCTL_CONFIG_DIR='* | source\ *transport-env*) continue ;;
    esac
    printf '%s\n' "$demo_line"
  done <.demo/env >"$demo_env_tmp"
  printf 'source %q\n' "$PWD/.demo/transport-env" >>"$demo_env_tmp"
  chmod 600 "$demo_env_tmp"
  mv "$demo_env_tmp" .demo/env
}

devctl_demo_owns_backend() {
  local backend_candidate="$1" backend_exe backend_cwd backend_argv0
  [[ "$backend_candidate" =~ ^[0-9]+$ ]] || return 1
  backend_exe="$(readlink "/proc/$backend_candidate/exe" 2>/dev/null || true)"
  if [[ "$backend_exe" == "$PWD/bin/devctld" || "$backend_exe" == "$PWD/bin/devctld (deleted)" ]]; then return 0; fi
  [[ "$backend_exe" == "$PWD/bin/.nfs"* ]] || return 1
  backend_cwd="$(readlink "/proc/$backend_candidate/cwd" 2>/dev/null || true)"
  [[ "$backend_cwd" == "$PWD" ]] || return 1
  IFS= read -r -d '' backend_argv0 <"/proc/$backend_candidate/cmdline" || return 1
  [[ "$backend_argv0" == './bin/devctld' || "$backend_argv0" == "$PWD/bin/devctld" ]]
}
