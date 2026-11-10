#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077

# Older demos kept Keycloak's H2 database in the container layer. Preserve that
# database before Compose replaces the container to add its persistent volume.
docker_cmd=(docker --host=unix:///var/run/docker.sock)
compose=("${docker_cmd[@]}" compose -f compose.yaml)
container="$("${compose[@]}" ps --all --quiet keycloak)"
[[ -n "$container" ]] || exit 0
[[ "$container" =~ ^[a-f0-9]+$ ]] || { echo 'Expected one demo Keycloak container; migration stopped.' >&2; exit 1; }

project="$("${docker_cmd[@]}" inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$container")"
[[ "$project" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { echo 'Cannot identify the demo Compose project; migration stopped.' >&2; exit 1; }
volume="${project}_keycloak-data"
mounted="$("${docker_cmd[@]}" inspect --format '{{range .Mounts}}{{if eq .Destination "/opt/keycloak/data/h2"}}{{.Type}}:{{.Name}}{{end}}{{end}}' "$container")"
[[ "$mounted" != "volume:$volume" ]] || exit 0
if [[ -n "$mounted" ]]; then
  echo 'Keycloak already uses different storage; refusing to replace it.' >&2
  exit 1
fi

# Reuse an already downloaded, pinned image from this Compose configuration.
# Its Alpine tools copy data without needing host bind mounts (including NFS).
helper_image=''
while IFS= read -r image; do
  case "$image" in postgres:*@sha256:*) helper_image="$image" ;; esac
done < <("${compose[@]}" config --images)
if [[ -z "$helper_image" ]] || ! "${docker_cmd[@]}" image inspect "$helper_image" >/dev/null 2>&1; then
  echo 'Keycloak migration needs the local PostgreSQL image; run docker compose pull postgres and retry.' >&2
  exit 1
fi
if "${docker_cmd[@]}" volume inspect "$volume" >/dev/null 2>&1; then
  owner="$("${docker_cmd[@]}" volume inspect --format '{{index .Labels "com.docker.compose.project"}}' "$volume")"
  logical_name="$("${docker_cmd[@]}" volume inspect --format '{{index .Labels "com.docker.compose.volume"}}' "$volume")"
  if [[ "$owner" != "$project" || "$logical_name" != keycloak-data ]]; then
    echo 'The target Keycloak volume is not owned by this demo; refusing to use it.' >&2
    exit 1
  fi
fi

mkdir -p .demo
chmod 700 .demo
backup="$(mktemp -d .demo/keycloak-migration.XXXXXX)"
echo "Preserving the existing Keycloak database in $backup before adding persistent storage."
"${docker_cmd[@]}" stop --time 30 "$container" >/dev/null
if ! "${docker_cmd[@]}" cp "$container:/opt/keycloak/data/h2" "$backup/h2"; then
  echo "Keycloak copy failed. Original container $container is retained; Compose was not run." >&2
  exit 1
fi
"${docker_cmd[@]}" volume create \
  --label "com.docker.compose.project=$project" \
  --label com.docker.compose.volume=keycloak-data "$volume" >/dev/null
if ! tar -C "$backup/h2" -cf - . | "${docker_cmd[@]}" run --rm -i \
  --network none --read-only --user 0:0 \
  --mount "type=volume,source=$volume,target=/target" \
  --entrypoint /bin/sh "$helper_image" -ec '
    # A completed copy can be retried before Compose recreates the old container.
    if [ -f /target/.devctl-keycloak-source ] && [ "$(cat /target/.devctl-keycloak-source)" = "$1" ]; then
      cat >/dev/null
      exit 0
    fi
    if [ -n "$(ls -A /target)" ]; then
      echo "Keycloak target volume contains unknown or incomplete data; refusing to overwrite it." >&2
      exit 1
    fi
    tar -xpf - -C /target
    chown -R 1000:0 /target
    chmod 700 /target
    printf "%s\n" "$1" > /target/.devctl-keycloak-source
  ' -- "$container"; then
  echo "Keycloak migration failed. Backup $backup and original container $container are retained; Compose was not run." >&2
  exit 1
fi
echo 'Keycloak database preserved in the demo volume; existing OIDC identities will be retained.'
