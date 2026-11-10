#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
mkdir -p dist
package_stage="$(mktemp -d dist/client.XXXXXX)"
trap 'rm -rf -- "$package_stage"' EXIT
install -m 755 bin/devctl "$package_stage/devctl"
install -m 755 scripts/install-client.sh "$package_stage/install.sh"
package_platform="$(go env GOOS)-$(go env GOARCH)"
package_path="dist/devctl-client-$package_platform.tar.gz"
tar -C "$package_stage" -czf "$package_path" devctl install.sh
printf '%s\n' "$PWD/$package_path"
