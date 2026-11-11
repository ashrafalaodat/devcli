#!/usr/bin/env bash
set -euo pipefail
umask 077
bundle_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
install_dir="${DEVCTL_INSTALL_DIR:-$HOME/.local/bin}"
shell_kind=''
shell_rc=''
setup_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --api|--issuer|--ca-file|--shell|--rc-file)
      [[ $# -ge 2 ]] || { echo "Missing value for $1" >&2; exit 2; }
      case "$1" in
        --api) export DEVCTL_API="$2" ;;
        --issuer) export DEVCTL_ISSUER="$2" ;;
        --ca-file) export DEVCTL_API_CA_FILE="$2" ;;
        --shell) shell_kind="$2" ;;
        --rc-file) shell_rc="$2" ;;
      esac
      shift 2 ;;
    *) setup_args+=("$1"); shift ;;
  esac
done
[[ -n "${DEVCTL_API:-}" && -n "${DEVCTL_ISSUER:-}" ]] || {
  echo 'Set --api and --issuer (or DEVCTL_API and DEVCTL_ISSUER) to the approved service URLs.' >&2
  exit 2
}
if [[ -n "$shell_rc" && -z "$shell_kind" ]]; then
  echo '--rc-file requires --shell bash, zsh, or fish.' >&2
  exit 2
fi
[[ -f "$bundle_dir/kubectl-devctl" ]] || { echo 'Extract the complete plugin archive before running install.sh.' >&2; exit 1; }
mkdir -p -- "$install_dir"
if [[ -L "$install_dir/kubectl-devctl" || ( -e "$install_dir/kubectl-devctl" && ! -f "$install_dir/kubectl-devctl" ) ]]; then
  echo 'The installation target must be a regular file; refusing to replace it.' >&2
  exit 1
fi
install -m 755 "$bundle_dir/kubectl-devctl" "$install_dir/kubectl-devctl"
active_config="$("$install_dir/kubectl-devctl" setup "${setup_args[@]}")"
if [[ -n "$shell_kind" ]]; then
  shell_args=(shell install --shell "$shell_kind")
  if [[ -n "$shell_rc" ]]; then shell_args+=(--rc-file "$shell_rc"); fi
  "$install_dir/kubectl-devctl" "${shell_args[@]}" >/dev/null
fi
printf 'Installed plugin: %s\nGateway kubeconfig: %s\n' "$install_dir/kubectl-devctl" "$active_config"
printf 'Ensure %s is on PATH so kubectl can discover the plugin.\n' "$install_dir"
if [[ -n "$shell_kind" ]]; then
  echo 'Open a new shell to load the gateway selection, then run kubectl.'
else
  echo 'For this Bash/Zsh terminal, run:'
  printf 'export KUBECONFIG=%q\n' "$active_config"
fi
echo 'Use kubectl devctl login to authenticate. Book a cluster using the web UI or full devctl CLI; this plugin does not book automatically.'
