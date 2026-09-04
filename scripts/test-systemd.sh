#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)

if [[ "$(id -u)" != 0 || "$(ps -p 1 -o comm= | tr -d ' ')" != systemd ]]; then
    printf '%s\n' 'scripts/test-systemd.sh: SUPPORTED_WITH_LIMITS (requires a systemd PID 1 and root)' >&2
    exit 0
fi
command -v systemctl >/dev/null 2>&1
command -v systemd-analyze >/dev/null 2>&1

test_dir=$(mktemp -d /run/antinat-p18-systemd.XXXXXX)
unit="antinat-p18-smoke-$$.service"
unit_path="/run/systemd/system/$unit"
cleanup() {
    systemctl stop "$unit" >/dev/null 2>&1 || true
    rm -f -- "$unit_path"
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -rf -- "$test_dir"
}
trap cleanup EXIT

# systemd-analyze checks ExecStart paths even for an offline verification. The
# checked files below are exact copies of the shipped units except for the
# executable path, which is redirected to a host-provided inert binary so no
# production path or service is touched.
agent_unit="$test_dir/antinat-agent.service"
controller_unit="$test_dir/antinat-controller.service"
sed 's|^ExecStart=/opt/antinat/bin/antinat-agent|ExecStart=/bin/true|' \
    "$repo_dir/deploy/systemd/antinat-agent.service" >"$agent_unit"
sed 's|^ExecStart=/opt/antinat/bin/antinat-controller|ExecStart=/bin/true|' \
    "$repo_dir/deploy/systemd/antinat-controller.service" >"$controller_unit"
unit_verify_log="$test_dir/antinat-units.log"
if ! systemd-analyze verify "$agent_unit" "$controller_unit" >"$unit_verify_log" 2>&1; then
    cat -- "$unit_verify_log" >&2
    exit 1
fi
grep -F -- 'User=antinat' "$agent_unit" >/dev/null
grep -F -- 'NoNewPrivileges=true' "$agent_unit" >/dev/null
grep -F -- 'CapabilityBoundingSet=' "$controller_unit" >/dev/null

printf '%s\n' \
    '[Unit]' \
    'Description=AntiNAT P18 systemd lifecycle smoke' \
    '' \
    '[Service]' \
    'Type=simple' \
    "ExecStart=/bin/sh -c 'printf \\\"start\\\\n\\\" >> $test_dir/events; while [ ! -e $test_dir/stop ]; do sleep 0.05; done'" \
    "ExecStop=/bin/sh -c 'printf \\\"stop\\\\n\\\" >> $test_dir/events'" \
    'Restart=no' \
    >"$unit_path"
chmod 644 -- "$unit_path"
verify_log="$test_dir/systemd-analyze.log"
if ! systemd-analyze verify "$unit_path" >"$verify_log" 2>&1; then
    if grep -F -- "$unit" "$verify_log" >/dev/null 2>&1; then
        cat -- "$verify_log" >&2
        exit 1
    fi
fi
systemctl daemon-reload

systemctl start "$unit"
timeout 5 sh -c "until systemctl is-active --quiet '$unit'; do sleep 0.05; done"
[[ "$(grep -c '^start$' "$test_dir/events")" == 1 ]]

systemctl restart "$unit"
timeout 5 sh -c "until systemctl is-active --quiet '$unit'; do sleep 0.05; done"
[[ "$(grep -c '^start$' "$test_dir/events")" == 2 ]]

touch -- "$test_dir/stop"
systemctl stop "$unit"
systemctl is-active --quiet "$unit" && exit 1 || true
[[ "$(grep -c '^stop$' "$test_dir/events")" -ge 1 ]]

ANTINAT_P18_TEST_TMP="$test_dir/installer" bash "$script_dir/test-installers.sh" >/dev/null
printf '%s\n' 'scripts/test-systemd.sh: SUPPORTED_WITH_LIMITS (systemd-analyze on redirected shipped-unit copies plus synthetic inert start/restart/stop; installer fresh/rollback/upgrade/purge remains isolated-test-root evidence)'
