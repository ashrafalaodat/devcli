#!/usr/bin/env bash
# Sourced from the repository root. Never signal an unrelated process based on a
# stale PID alone. NFS keeps running replaced binaries under a .nfs filename.
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
