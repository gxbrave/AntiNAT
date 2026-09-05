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

assert_tree_matches() {
    local actual="$1" expected="$2" message="$3"
    diff -r --no-dereference -- "$expected" "$actual" >/dev/null || {
        echo "$message" >&2
        exit 1
    }
    diff \
        <(find "$expected" -printf '%P\t%y\t%m\t%u\t%g\n' | sort) \
        <(find "$actual" -printf '%P\t%y\t%m\t%u\t%g\n' | sort) >/dev/null || {
        echo "$message (metadata differs)" >&2
        exit 1
    }
}

make_release old-binary

# Online removal must obtain the Agent's durable Controller receipt before it
# stops the service. The normal Linux path is the shipped private Unix socket,
# not an externally provisioned helper.
uninstall_notice_line=$(grep -n 'installer_remote_uninstall_notice ||' "$repo_dir/scripts/libinstall.sh" | cut -d: -f1)
uninstall_stop_line=$(sed -n "${uninstall_notice_line},$((uninstall_notice_line + 3))p" "$repo_dir/scripts/libinstall.sh" | grep -n 'installer_stop_service ||' | cut -d: -f1)
purge_notice_line=$(grep -n 'installer_remote_uninstall_notice purge ||' "$repo_dir/scripts/libinstall.sh" | cut -d: -f1)
purge_stop_line=$(sed -n "${purge_notice_line},$((purge_notice_line + 3))p" "$repo_dir/scripts/libinstall.sh" | grep -n 'installer_stop_service ||' | cut -d: -f1)
[[ "$uninstall_stop_line" == 2 && "$purge_stop_line" == 2 ]] || {
    echo 'uninstall notice is not completed before service stop' >&2
    exit 1
}
grep -F -- '--unix-socket "$socket"' "$repo_dir/scripts/libinstall.sh" >/dev/null
grep -F -- '.status == "RECEIPTED"' "$repo_dir/scripts/libinstall.sh" >/dev/null
force_line=$(grep -n '\[\[ "${ANTINAT_FORCE_OFFLINE_PURGE:-0}" == 1 \]\] && return 0' "$repo_dir/scripts/libinstall.sh" | cut -d: -f1)
socket_line=$(grep -n 'if \[\[ -S "$socket"' "$repo_dir/scripts/libinstall.sh" | cut -d: -f1)
[[ -n "$force_line" && -n "$socket_line" && "$force_line" -lt "$socket_line" ]] || {
    echo 'forced-offline purge does not bypass an unusable Agent socket' >&2
    exit 1
}
if grep -F 'ANTINAT_UNINSTALL_NOTICE_HELPER' "$repo_dir/scripts/libinstall.sh" >/dev/null; then
    echo 'Linux uninstall still depends on an external notice helper' >&2
    exit 1
fi

# OpenRC sources agent.conf as root. Every generated value must remain data,
# including a single quote followed by valid shell commands.
openrc_root="$cache_dir/openrc-quote-root"
openrc_payload="'; INJECTED=yes; #"
ANTINAT_SERVICE_MANAGER=openrc run_installer_root "$openrc_root" install \
    --controller-endpoint https://controller.example --bind-interface "$openrc_payload" >/dev/null
openrc_values=$(env -i sh -c '. "$1"; printf "%s\n%s\n" "$ANTINAT_BIND_INTERFACE" "${INJECTED-unset}"' \
    _ "$openrc_root/etc/antinat/agent.conf")
[[ "$openrc_values" == "$openrc_payload"$'\n'unset ]] || {
    echo 'OpenRC config allowed bind-interface shell injection' >&2
    exit 1
}

# A failed enrollment after files are staged must roll back the fresh install
# and leave the retryable source token in place.
enrollment_root="$cache_dir/enrollment-failure-root"
enrollment_token="$cache_dir/enrollment-failure-token"
printf '%s\n' enrollment-token >"$enrollment_token"
chmod 600 -- "$enrollment_token"
set +e
ANTINAT_TEST_FAIL_POINT=enrollment run_installer_root "$enrollment_root" install \
    --controller-endpoint https://controller.example --token-file "$enrollment_token" >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 3 ]] || { echo "failed enrollment exit=$status, want 3" >&2; exit 1; }
[[ -f "$enrollment_token" ]] || { echo 'failed enrollment consumed retry token' >&2; exit 1; }
[[ ! -e "$enrollment_root/opt/antinat/bin/antinat-agent" ]] || { echo 'failed enrollment left Agent binary' >&2; exit 1; }

# A deterministic, test-only write fault stands in for ENOSPC. Rollback must
# preserve every retained Agent/Controller resource byte-for-byte.
retained_root="$cache_dir/retained-state-root"
mkdir -p -- "$retained_root/var/lib/antinat/controller-keys" "$retained_root/etc/antinat" \
    "$retained_root/var/log/antinat"
printf '%s\n' retained-state >"$retained_root/var/lib/antinat/state.db"
printf '%s\n' retained-node-key >"$retained_root/var/lib/antinat/node.key"
printf '%s\n' retained-terminal >"$retained_root/var/lib/antinat/terminal.marker"
printf '%s\n' retained-agent >"$retained_root/var/lib/antinat/agent.marker"
printf '%s\n' retained-controller >"$retained_root/var/lib/antinat/controller.db"
printf '%s\n' retained-wal >"$retained_root/var/lib/antinat/controller.db-wal"
printf '%s\n' retained-shm >"$retained_root/var/lib/antinat/controller.db-shm"
printf '%s\n' retained-controller-key >"$retained_root/var/lib/antinat/controller-keys/key.pem"
printf '%s\n' 2 >"$retained_root/var/lib/antinat/schema.version"
printf '%s\n' retained-ownership >"$retained_root/var/lib/antinat/ownership-manifest.json"
printf '%s\n' retained-ownership-key >"$retained_root/var/lib/antinat/ownership.key"
printf '%s\n' retained-config >"$retained_root/etc/antinat/agent.conf"
printf '%s\n' retained-log >"$retained_root/var/log/antinat/agent.log"
chmod 600 -- "$retained_root"/var/lib/antinat/{state.db,node.key,terminal.marker,agent.marker,controller.db,controller.db-wal,controller.db-shm,schema.version,ownership-manifest.json,ownership.key} \
    "$retained_root/var/lib/antinat/controller-keys/key.pem" "$retained_root/etc/antinat/agent.conf"
retained_snapshot="$cache_dir/retained-state-snapshot"
cp -a -- "$retained_root" "$retained_snapshot"
set +e
ANTINAT_ROLE=both ANTINAT_TEST_FAIL_POINT=write run_installer_root "$retained_root" install \
    --controller-endpoint https://controller.example >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 1 ]] || { echo "ENOSPC-like install failure exit=$status, want 1" >&2; exit 1; }
assert_tree_matches "$retained_root/var/lib/antinat" "$retained_snapshot/var/lib/antinat" 'failed reinstall did not restore retained data'
assert_tree_matches "$retained_root/etc/antinat" "$retained_snapshot/etc/antinat" 'failed reinstall did not restore retained config'
assert_tree_matches "$retained_root/var/log/antinat" "$retained_snapshot/var/log/antinat" 'failed reinstall did not restore retained logs'

# A Controller install must reject an occupied native listener before writing
# package state.
port_root="$cache_dir/port-conflict-root"
port_ready="$cache_dir/port-holder-ready"
python3 -c 'import socket, sys, time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 3111)); s.listen(); open(sys.argv[1], "w").close(); time.sleep(30)' "$port_ready" &
port_holder=$!
trap 'kill "$port_holder" 2>/dev/null || true; rm -rf -- "$cache_dir"' EXIT
for _ in {1..50}; do
    [[ -e "$port_ready" ]] && break
    sleep 0.02
done
[[ -e "$port_ready" ]] || { echo 'port-conflict fixture did not become ready' >&2; exit 1; }
set +e
run_installer_role controller "$port_root" install >/dev/null 2>&1
status=$?
set -e
kill "$port_holder" 2>/dev/null || true
wait "$port_holder" 2>/dev/null || true
trap 'rm -rf -- "$cache_dir"' EXIT
[[ "$status" == 5 ]] || { echo "port conflict exit=$status, want 5" >&2; exit 1; }
[[ ! -e "$port_root/opt/antinat/bin/antinat-controller" ]] || { echo 'port conflict changed install state' >&2; exit 1; }

token_file="$cache_dir/token"
token_value=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
printf '%s\n' "$token_value" >"$token_file"
chmod 600 -- "$token_file"
run_installer install --controller-endpoint https://controller.example --platform linux \
    --bind-interface eth0 --log-level debug --auto-update stable \
    --github-proxy https://proxy.example --detection-scheduler parallel \
    --token-file "$token_file" >/dev/null
[[ ! -e "$token_file" ]] || { echo 'token source was not consumed' >&2; exit 1; }
[[ "$(cat "$root/opt/antinat/bin/antinat-agent")" == old-binary ]] || { echo 'initial artifact missing' >&2; exit 1; }
[[ "$(cat "$root/var/lib/antinat/schema.version")" == 3 ]] || { echo 'schema marker missing from install' >&2; exit 1; }
[[ "$(stat -c '%a' "$root/etc/antinat/agent.conf")" == 600 ]] || { echo 'agent config mode is not 0600' >&2; exit 1; }
jq -e '.resources[] | select(.path == "schema.version")' "$root/var/lib/antinat/ownership-manifest.json" >/dev/null || { echo 'schema marker missing from ownership manifest' >&2; exit 1; }
jq -e '.resources[] | select(.path == "antinat" and .root == "'"$root"'/var/log")' "$root/var/lib/antinat/ownership-manifest.json" >/dev/null || { echo 'log directory missing from ownership manifest' >&2; exit 1; }
printf '%s\n' owned-log-entry >"$root/var/log/antinat/agent.log"
grep -F -x -- "ANTINAT_BIND_INTERFACE='eth0'" "$root/etc/antinat/agent.conf" >/dev/null || { echo 'bind option missing from config' >&2; exit 1; }
grep -F -x -- "ANTINAT_LOG_LEVEL='debug'" "$root/etc/antinat/agent.conf" >/dev/null || { echo 'log option missing from config' >&2; exit 1; }
grep -F -x -- "ANTINAT_AUTO_UPDATE='stable'" "$root/etc/antinat/agent.conf" >/dev/null || { echo 'auto-update option missing from config' >&2; exit 1; }
grep -F -x -- "ANTINAT_DETECTION_SCHEDULER='parallel'" "$root/etc/antinat/agent.conf" >/dev/null || { echo 'scheduler option missing from config' >&2; exit 1; }
grep -F -x -- "ANTINAT_GITHUB_PROXY='https://proxy.example'" "$root/etc/antinat/agent.conf" >/dev/null || { echo 'GitHub proxy missing from config' >&2; exit 1; }
needle_file="$cache_dir/token-needle"
printf '%s\n' "$token_value" >"$needle_file"
! grep -R -F -f "$needle_file" "$root" >/dev/null 2>&1 || { echo 'token leaked to installed state' >&2; exit 1; }
rm -f -- "$needle_file"
unset token_value

set +e
run_installer install --controller-endpoint https://controller.example --platform linux >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 5 ]] || { echo "repeat install exit=$status, want 5" >&2; exit 1; }

exec {upgrade_lock_fd}>>"$root/var/lib/antinat/.upgrade.lock"
flock -n "$upgrade_lock_fd"
set +e
run_installer upgrade >/dev/null 2>&1
status=$?
set -e
flock -u "$upgrade_lock_fd"
exec {upgrade_lock_fd}>&-
[[ "$status" == 5 ]] || { echo "upgrade lock contention exit=$status, want 5" >&2; exit 1; }

make_release new-binary
# Seed every Agent-owned upgrade resource so the health-gated rollback proves
# the complete snapshot is restored, not only the executable.
mkdir -p -- "$root/var/lib/antinat"
printf '%s\n' state-before-upgrade >"$root/var/lib/antinat/state.db"
printf '%s\n' key-before-upgrade >"$root/var/lib/antinat/node.key"
printf '%s\n' terminal-before-upgrade >"$root/var/lib/antinat/terminal.marker"
printf '%s\n' agent-before-upgrade >"$root/var/lib/antinat/agent.marker"
rollback_snapshot="$cache_dir/rollback-snapshot"
mkdir -p -- "$rollback_snapshot"
rollback_paths=(
    opt/antinat/bin/antinat-agent
    opt/antinat/bin/antinat-hook-runner
    etc/antinat/agent.conf
    etc/systemd/system/antinat-agent.service
    var/lib/antinat/state.db
    var/lib/antinat/node.key
    var/lib/antinat/terminal.marker
    var/lib/antinat/agent.marker
    var/lib/antinat/schema.version
    var/lib/antinat/ownership-manifest.json
    var/lib/antinat/ownership.key
)
for relative in "${rollback_paths[@]}"; do
    mkdir -p -- "$rollback_snapshot/$(dirname -- "$relative")"
    cp -p -- "$root/$relative" "$rollback_snapshot/$relative"
done
set +e
ANTINAT_FORCE_HEALTH_FAIL=1 \
ANTINAT_TEST_MODE=1 ANTINAT_TEST_ROOT="$root" ANTINAT_ARTIFACT_DIR="$artifacts" \
ANTINAT_TRUST_ROOT_FILE="$cache_dir/release.pub" ANTINAT_TRUST_ROOT_ID=release-key-2026 \
bash "$repo_dir/scripts/install.sh" upgrade >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 6 ]] || { echo "failed upgrade exit=$status, want 6" >&2; exit 1; }
# Rollback must quiesce the newly promoted services before restoring mutable
# state, then start the restored service set. The test-mode service wrapper is
# inert, so assert this safety ordering directly against the shipped function.
rollback_body=$(sed -n '/if ((failed != 0)); then/,/return "$INSTALLER_EXIT_ROLLBACK"/p' "$repo_dir/scripts/libinstall.sh")
rollback_stop_line=$(grep -n 'installer_stop_service || rollback_failed=1' <<<"$rollback_body" | cut -d: -f1)
rollback_restore_line=$(grep -n 'installer_restore_snapshot "$backup" || rollback_failed=1' <<<"$rollback_body" | cut -d: -f1)
[[ -n "$rollback_stop_line" && -n "$rollback_restore_line" && "$rollback_stop_line" -lt "$rollback_restore_line" ]] || {
    echo 'upgrade rollback restores live state before stopping promoted services' >&2
    exit 1
}
for relative in "${rollback_paths[@]}"; do
    cmp -- "$root/$relative" "$rollback_snapshot/$relative" || { echo "rollback did not restore $relative" >&2; exit 1; }
done

# A failure persisting the final completion record happens after health checks
# and service start. It must use the same quiesced restore path and leave the
# previous installation fully recoverable.
set +e
ANTINAT_TEST_FAIL_POINT=complete_journal \
ANTINAT_TEST_MODE=1 ANTINAT_TEST_ROOT="$root" ANTINAT_ARTIFACT_DIR="$artifacts" \
ANTINAT_TRUST_ROOT_FILE="$cache_dir/release.pub" ANTINAT_TRUST_ROOT_ID=release-key-2026 \
bash "$repo_dir/scripts/install.sh" upgrade >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 6 ]] || { echo "completion journal failure exit=$status, want 6" >&2; exit 1; }
for relative in "${rollback_paths[@]}"; do
    cmp -- "$root/$relative" "$rollback_snapshot/$relative" || { echo "completion journal rollback did not restore $relative" >&2; exit 1; }
done
completion_rollback_body=$(sed -n '/if installer_test_fail_at complete_journal/,/return "$INSTALLER_EXIT_ROLLBACK"/p' "$repo_dir/scripts/libinstall.sh")
completion_stop_line=$(grep -n 'installer_stop_service || rollback_failed=1' <<<"$completion_rollback_body" | cut -d: -f1)
completion_restore_line=$(grep -n 'installer_restore_snapshot "$backup" || rollback_failed=1' <<<"$completion_rollback_body" | cut -d: -f1)
completion_start_line=$(grep -n 'installer_start_services || rollback_failed=1' <<<"$completion_rollback_body" | cut -d: -f1)
[[ -n "$completion_stop_line" && -n "$completion_restore_line" && -n "$completion_start_line" && \
   "$completion_stop_line" -lt "$completion_restore_line" && "$completion_restore_line" -lt "$completion_start_line" ]] || {
    echo 'completion journal rollback is not quiesce, restore, then restart' >&2
    exit 1
}

set +e
ANTINAT_FAIL_MIGRATION=1 run_installer upgrade >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 6 ]] || { echo "migration failure exit=$status, want 6" >&2; exit 1; }
for relative in "${rollback_paths[@]}"; do
    cmp -- "$root/$relative" "$rollback_snapshot/$relative" || { echo "migration rollback did not restore $relative" >&2; exit 1; }
done

# The failed upgrade leaves a durable journal. Reopen its state as if the
# process crashed during promotion; the next upgrade must recover the old
# artifact before taking its new snapshot.
recovery_candidate=$(find "$root/var/lib/antinat/backups" -mindepth 1 -maxdepth 1 -type d -name 'upgrade.*' -print | sort | tail -n 1)
[[ -n "$recovery_candidate" && -f "$recovery_candidate/transaction.json" ]] || { echo 'upgrade transaction journal was not created' >&2; exit 1; }
jq '.state = "promoting"' "$recovery_candidate/transaction.json" >"$cache_dir/recovery-journal.json"
mv -- "$cache_dir/recovery-journal.json" "$recovery_candidate/transaction.json"
chmod 600 -- "$recovery_candidate/transaction.json"
printf '%s\n' tampered-after-crash >"$root/opt/antinat/bin/antinat-agent"
set +e
ANTINAT_FORCE_HEALTH_FAIL=1 run_installer upgrade >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 6 ]] || { echo "interrupted upgrade recovery exit=$status, want 6" >&2; exit 1; }
cmp -- "$root/opt/antinat/bin/antinat-agent" "$rollback_snapshot/opt/antinat/bin/antinat-agent" || { echo 'interrupted upgrade recovery did not restore the pre-crash artifact' >&2; exit 1; }

# A durable interrupted-upgrade snapshot includes an explicit placeholder for
# every absent resource. Recovery must accept that record shape before taking
# the next snapshot.
absent_candidate="$root/var/lib/antinat/backups/upgrade.absent"
mkdir -p -- "$absent_candidate"
chmod 700 -- "$absent_candidate"
# Start from the complete durable snapshot. Recovery validates the whole
# resource set, so a one-row fixture would exercise only the parser and not
# the actual interrupted-upgrade contract.
cp -p -- "$recovery_candidate"/file-* "$absent_candidate"/
awk -F '\t' -v OFS='\t' -v absent_root="$root/var/lib/antinat" \
    '$3 == absent_root && $4 == "terminal.marker" {
        $1 = 0; $2 = "none"; $5 = "-"; $6 = "-"; $7 = "-"; $8 = "-"
    }
    { print }' "$recovery_candidate/snapshot.tsv" >"$absent_candidate/snapshot.tsv"
chmod 600 -- "$absent_candidate/snapshot.tsv"
printf '%s\n' '{"schema":"antinat.shell-upgrade/v1","live_root":"'"$root/opt/antinat"'","backup_path":"'"$absent_candidate"'","snapshot":"snapshot.tsv","state":"promoting","completed":[],"agent_was_active":false,"controller_was_active":false,"agent_was_enabled":false,"controller_was_enabled":false}' >"$absent_candidate/transaction.json"
chmod 600 -- "$absent_candidate/transaction.json"
set +e
ANTINAT_FORCE_HEALTH_FAIL=1 run_installer upgrade >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 6 ]] || { echo "absent-resource recovery exit=$status, want 6" >&2; exit 1; }

# A missing marker is the explicitly supported legacy N-1 state.
rm -f -- "$root/var/lib/antinat/schema.version"
run_installer upgrade >/dev/null
[[ "$(cat "$root/opt/antinat/bin/antinat-agent")" == new-binary ]] || { echo 'legacy upgrade was not accepted' >&2; exit 1; }

# A present N-1 marker is accepted, while a regression and a skipped version
# are rejected before artifact installation begins.
make_release newer-binary
printf '%s\n' 2 >"$root/var/lib/antinat/schema.version"
run_installer upgrade >/dev/null
[[ "$(cat "$root/opt/antinat/bin/antinat-agent")" == newer-binary ]] || { echo 'N-1 upgrade was not accepted' >&2; exit 1; }
printf '%s\n' 1 >"$root/var/lib/antinat/schema.version"
set +e
run_installer upgrade >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 8 ]] || { echo "regression upgrade exit=$status, want 8" >&2; exit 1; }
printf '%s\n' 4 >"$root/var/lib/antinat/schema.version"
set +e
run_installer upgrade >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 8 ]] || { echo "skipped-version upgrade exit=$status, want 8" >&2; exit 1; }
printf '%s\n' 3 >"$root/var/lib/antinat/schema.version"
run_installer upgrade >/dev/null
[[ "$(cat "$root/opt/antinat/bin/antinat-agent")" == newer-binary ]] || { echo 'same-version upgrade missing binary' >&2; exit 1; }

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
printf '%s' alternate-hook >"$artifacts/alternate-antinat-hook-runner-linux-amd64"
alternate_hook_digest=$(sha256sum "$artifacts/alternate-antinat-hook-runner-linux-amd64" | awk '{print $1}')
jq --arg digest "$alternate_hook_digest" '.artifacts["alternate-antinat-hook-runner-linux-amd64"] = $digest' \
    "$artifacts/manifest.json" >"$cache_dir/role-failure-manifest.json"
mv -- "$cache_dir/role-failure-manifest.json" "$artifacts/manifest.json"
openssl pkeyutl -sign -rawin -inkey "$cache_dir/release.key" -in "$artifacts/manifest.json" -out "$artifacts/manifest.sig" 2>/dev/null
printf '%s\n' 2 >"$role_root/var/lib/antinat/schema.version"
role_schema_before=$(cat "$role_root/var/lib/antinat/schema.version")
od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"$cache_dir/role-failure-token"
chmod 600 -- "$cache_dir/role-failure-token"
set +e
run_installer_role agent "$role_root" install --controller-endpoint https://controller.example --token-file "$cache_dir/role-failure-token" >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 4 ]] || { echo "failed role install exit=$status, want 4" >&2; exit 1; }
[[ -f "$role_root/opt/antinat/bin/antinat-controller" ]] || { echo 'failed role install removed controller' >&2; exit 1; }
[[ "$(cat "$role_root/var/lib/antinat/schema.version")" == "$role_schema_before" ]] || { echo 'failed role install changed shared schema marker' >&2; exit 1; }
[[ -f "$role_root/var/lib/antinat/ownership-manifest.json" && -f "$role_root/var/lib/antinat/ownership.key" ]] || { echo 'failed role install removed ownership metadata' >&2; exit 1; }
[[ -f "$cache_dir/role-failure-token" ]] || { echo 'failed role install consumed retry token' >&2; exit 1; }
rm -f -- "$cache_dir/role-failure-token"
make_release new-binary
od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"$cache_dir/role-token"
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

od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"$cache_dir/bad-token"
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
[[ ! -e "$root/var/log/antinat" ]] || { echo 'purge left log residue' >&2; exit 1; }

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
[[ ! -e "$fallback_root/var/lib/antinat/schema.version" ]] || { echo 'fallback purge left the schema marker after the last role was removed' >&2; exit 1; }

symlink_root="$cache_dir/symlink-root"
run_installer_root "$symlink_root" install --controller-endpoint https://controller.example >/dev/null
rm -f -- "$symlink_root/var/lib/antinat/schema.version"
ln -s -- outside-schema-marker "$symlink_root/var/lib/antinat/schema.version"
set +e
run_installer_root "$symlink_root" upgrade >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 8 ]] || { echo "dangling schema marker upgrade exit=$status, want 8" >&2; exit 1; }
[[ -L "$symlink_root/var/lib/antinat/schema.version" ]] || { echo 'dangling schema marker was changed during blocked upgrade' >&2; exit 1; }

echo 'scripts/test-installers.sh: PASS'
