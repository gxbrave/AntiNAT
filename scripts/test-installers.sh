#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)
cache_dir="${ANTINAT_P18_TEST_TMP:-${TMPDIR:-/tmp}/antinat-p18-installer-tests}"
rm -rf -- "$cache_dir"
mkdir -p -- "$cache_dir"
trap 'rm -rf -- "$cache_dir"' EXIT

command -v jq >/dev/null 2>&1 || { echo 'jq is required' >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo 'openssl is required' >&2; exit 1; }

root="$cache_dir/root"
artifacts="$cache_dir/artifacts"
mkdir -p -- "$root" "$artifacts"
chmod 700 -- "$artifacts"
openssl genpkey -algorithm Ed25519 -out "$cache_dir/release.key" 2>/dev/null
openssl pkey -in "$cache_dir/release.key" -pubout -out "$cache_dir/release.pub" 2>/dev/null

make_release() {
    local content="$1"
    printf '%s' "$content" >"$artifacts/antinat-agent-linux-amd64"
    printf '%s' controller-binary >"$artifacts/antinat-controller-linux-amd64"
    printf '%s' hook-binary >"$artifacts/antinat-hook-runner-linux-amd64"
    local agent_digest controller_digest hook_digest manifest
    agent_digest=$(sha256sum "$artifacts/antinat-agent-linux-amd64" | awk '{print $1}')
    controller_digest=$(sha256sum "$artifacts/antinat-controller-linux-amd64" | awk '{print $1}')
    hook_digest=$(sha256sum "$artifacts/antinat-hook-runner-linux-amd64" | awk '{print $1}')
    manifest=$(jq -cn --arg agent "$agent_digest" --arg controller "$controller_digest" --arg hook "$hook_digest" '{schema_version:"1",release:"test",artifacts:{"antinat-agent-linux-amd64":$agent,"antinat-controller-linux-amd64":$controller,"antinat-hook-runner-linux-amd64":$hook},trust_root:"release-key-2026",signature_algorithm:"ed25519"}')
    printf '%s' "$manifest" >"$artifacts/manifest.json"
    openssl pkeyutl -sign -rawin -inkey "$cache_dir/release.key" -in "$artifacts/manifest.json" -out "$artifacts/manifest.sig" 2>/dev/null
}

run_installer_root() {
    local test_root="$1"
    shift
    ANTINAT_TEST_MODE=1 \
    ANTINAT_TEST_ROOT="$test_root" \
    ANTINAT_ARTIFACT_DIR="$artifacts" \
    ANTINAT_TRUST_ROOT_FILE="$cache_dir/release.pub" \
    ANTINAT_TRUST_ROOT_ID=release-key-2026 \
    bash "$repo_dir/scripts/install.sh" "$@"
}

run_installer() {
    run_installer_root "$root" "$@"
}

run_installer_role() {
    local role="$1" test_root="$2"
    shift 2
    ANTINAT_ROLE="$role" run_installer_root "$test_root" "$@"
}

make_release old-binary
token_file="$cache_dir/token"
printf '%s\n' installer-secret >"$token_file"
chmod 600 -- "$token_file"
run_installer install --controller-endpoint https://controller.example --platform linux --token-file "$token_file" >/dev/null
[[ ! -e "$token_file" ]] || { echo 'token source was not consumed' >&2; exit 1; }
[[ "$(cat "$root/opt/antinat/bin/antinat-agent")" == old-binary ]] || { echo 'initial artifact missing' >&2; exit 1; }
! grep -R --fixed-strings installer-secret "$root" >/dev/null 2>&1 || { echo 'token leaked to installed state' >&2; exit 1; }

set +e
run_installer install --controller-endpoint https://controller.example --platform linux >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 5 ]] || { echo "repeat install exit=$status, want 5" >&2; exit 1; }

make_release new-binary
set +e
ANTINAT_FORCE_HEALTH_FAIL=1 \
ANTINAT_TEST_MODE=1 ANTINAT_TEST_ROOT="$root" ANTINAT_ARTIFACT_DIR="$artifacts" \
ANTINAT_TRUST_ROOT_FILE="$cache_dir/release.pub" ANTINAT_TRUST_ROOT_ID=release-key-2026 \
bash "$repo_dir/scripts/install.sh" upgrade >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 6 ]] || { echo "failed upgrade exit=$status, want 6" >&2; exit 1; }
[[ "$(cat "$root/opt/antinat/bin/antinat-agent")" == old-binary ]] || { echo 'rollback did not restore binary' >&2; exit 1; }
run_installer upgrade >/dev/null
[[ "$(cat "$root/opt/antinat/bin/antinat-agent")" == new-binary ]] || { echo 'successful upgrade missing new binary' >&2; exit 1; }

# A signed manifest with two candidates for one role is rejected instead of
# selecting an arbitrary artifact by sorted order.
printf '%s' ambiguous-binary >"$artifacts/alternate-antinat-agent-linux-amd64"
alternate_digest=$(sha256sum "$artifacts/alternate-antinat-agent-linux-amd64" | awk '{print $1}')
jq --arg digest "$alternate_digest" '.artifacts["alternate-antinat-agent-linux-amd64"] = $digest' \
    "$artifacts/manifest.json" >"$cache_dir/ambiguous-manifest.json"
mv -- "$cache_dir/ambiguous-manifest.json" "$artifacts/manifest.json"
openssl pkeyutl -sign -rawin -inkey "$cache_dir/release.key" -in "$artifacts/manifest.json" -out "$artifacts/manifest.sig" 2>/dev/null
duplicate_root="$cache_dir/duplicate-root"
set +e
run_installer_root "$duplicate_root" install --controller-endpoint https://controller.example --platform linux >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 4 ]] || { echo "ambiguous artifact exit=$status, want 4" >&2; exit 1; }
[[ ! -e "$duplicate_root/opt/antinat/bin/antinat-agent" ]] || { echo 'ambiguous artifact changed install state' >&2; exit 1; }
make_release new-binary

role_root="$cache_dir/role-root"
run_installer_role controller "$role_root" install >/dev/null
[[ -f "$role_root/opt/antinat/bin/antinat-controller" ]] || { echo 'controller-only install missing controller' >&2; exit 1; }
[[ ! -e "$role_root/opt/antinat/bin/antinat-agent" ]] || { echo 'controller-only install created agent' >&2; exit 1; }
printf '%s\n' role-isolation-token >"$cache_dir/role-token"
chmod 600 -- "$cache_dir/role-token"
run_installer_role agent "$role_root" install --controller-endpoint https://controller.example --token-file "$cache_dir/role-token" >/dev/null
[[ ! -e "$cache_dir/role-token" ]] || { echo 'role token source was not consumed' >&2; exit 1; }
jq -e '.resources[] | select(.path == "bin/antinat-controller")' "$role_root/var/lib/antinat/ownership-manifest.json" >/dev/null || { echo 'role install overwrote controller ownership' >&2; exit 1; }
run_installer_role agent "$role_root" uninstall >/dev/null
[[ -f "$role_root/opt/antinat/bin/antinat-controller" ]] || { echo 'agent uninstall removed controller' >&2; exit 1; }
[[ -f "$role_root/etc/systemd/system/antinat-controller.service" ]] || { echo 'agent uninstall removed controller service' >&2; exit 1; }
set +e
run_installer_role controller "$role_root" purge >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 7 ]] || { echo "controller role purge exit=$status, want 7" >&2; exit 1; }
[[ -e "$role_root/var/lib/antinat/ownership-manifest.json" ]] || { echo 'controller purge removed shared ownership from agent' >&2; exit 1; }
set +e
run_installer_role agent "$role_root" purge >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 7 ]] || { echo "agent role purge exit=$status, want 7" >&2; exit 1; }
[[ ! -e "$role_root/var/lib/antinat/ownership-manifest.json" && ! -e "$role_root/opt/antinat" ]] || { echo 'last role purge left ownership residue' >&2; exit 1; }

printf '%s\n' bad-secret >"$cache_dir/bad-token"
chmod 644 -- "$cache_dir/bad-token"
set +e
run_installer_root "$cache_dir/bad-root" install --controller-endpoint https://controller.example --platform linux --token-file "$cache_dir/bad-token" >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 3 ]] || { echo "bad token mode exit=$status, want 3" >&2; exit 1; }

cp -- "$artifacts/manifest.sig" "$cache_dir/good.sig"
printf 'tampered' >"$artifacts/manifest.sig"
set +e
run_installer install --controller-endpoint https://controller.example --platform linux >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 4 ]] || { echo "bad signature exit=$status, want 4" >&2; exit 1; }
cp -- "$cache_dir/good.sig" "$artifacts/manifest.sig"

set +e
run_installer purge --platform linux >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 7 ]] || { echo "purge exit=$status, want 7" >&2; exit 1; }
[[ ! -e "$root/opt/antinat/bin/antinat-agent" ]] || { echo 'purge left executable residue' >&2; exit 1; }
[[ ! -e "$root/etc/antinat/agent.conf" ]] || { echo 'purge left config residue' >&2; exit 1; }

fallback_root="$cache_dir/fallback-root"
run_installer_root "$fallback_root" install --controller-endpoint https://controller.example >/dev/null
printf '{invalid' >"$fallback_root/var/lib/antinat/ownership-manifest.json"
set +e
fallback_output=$(run_installer_root "$fallback_root" purge --platform linux 2>&1)
status=$?
set -e
[[ "$status" == 7 ]] || { echo "fallback purge exit=$status, want 7" >&2; exit 1; }
[[ "$fallback_output" != *'another role and shared ownership state remain'* ]] || { echo 'fallback purge reported a surviving role from an invalid manifest' >&2; exit 1; }
[[ "$fallback_output" == *'ownership metadata retained'* ]] || { echo 'fallback purge overstated residue removal' >&2; exit 1; }

echo 'scripts/test-installers.sh: PASS'
