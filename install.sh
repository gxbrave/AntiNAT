#!/usr/bin/env bash

# Raw GitHub bootstrap. The signed release manifest remains the trust boundary;
# this file only stages the release installer and its pinned public key.
set -euo pipefail

release_version="${ANTINAT_RELEASE_VERSION:-v1.0.0-beta.1}"
release_base_url="${ANTINAT_RELEASE_BASE_URL:-https://github.com/gxbrave/AntiNAT/releases/download/$release_version}"

[[ "$release_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-beta\.[0-9]+$ ]] || {
    printf 'antinat bootstrap: invalid release version\n' >&2
    exit 2
}
[[ "$release_base_url" != *"@"* && "$release_base_url" =~ ^https://[^[:space:]/?#]+(/[^[:space:]?#]*)?$ ]] || {
    printf 'antinat bootstrap: invalid release URL\n' >&2
    exit 4
}

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/antinat-installer.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT
mkdir -p -- "$tmp_dir/scripts" "$tmp_dir/deploy/trust"

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "$release_base_url/libinstall.sh" -o "$tmp_dir/scripts/libinstall.sh"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "$release_base_url/release-ed25519.pub" -o "$tmp_dir/deploy/trust/release-ed25519.pub"
chmod 700 -- "$tmp_dir" "$tmp_dir/scripts" "$tmp_dir/deploy" "$tmp_dir/deploy/trust"
chmod 600 -- "$tmp_dir/scripts/libinstall.sh" "$tmp_dir/deploy/trust/release-ed25519.pub"

# shellcheck source=/dev/null
source "$tmp_dir/scripts/libinstall.sh"
installer_run "$@"
