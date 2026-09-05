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
command -v curl >/dev/null 2>&1
command -v go >/dev/null 2>&1
command -v python3 >/dev/null 2>&1

test_dir=$(mktemp -d /tmp/antinat-p18-systemd.XXXXXX)
unit="antinat-p18-smoke-$$.service"
unit_path="/run/systemd/system/$unit"
cleanup() {
    systemctl stop "$unit" >/dev/null 2>&1 || true
    systemctl disable --runtime "$unit" >/dev/null 2>&1 || true
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
grep -F -- 'WantedBy=multi-user.target' "$agent_unit" >/dev/null
grep -F -- 'WantedBy=multi-user.target' "$controller_unit" >/dev/null

controller_binary="$test_dir/antinat-controller"
GOWORK=off go build -buildvcs=false -o "$controller_binary" "$repo_dir/cmd/antinat-controller"
chmod 755 -- "$controller_binary"
controller_store="$test_dir/controller.db"
controller_keydir="$test_dir/controller-keys"
mkdir -p -- "$controller_keydir"
chmod 700 -- "$controller_keydir"
controller_port=$(python3 - <<'PY'
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
)

printf '%s\n' \
    '[Unit]' \
    'Description=AntiNAT P18 controller lifecycle smoke' \
    '' \
    '[Service]' \
    'Type=simple' \
    "ExecStart=$controller_binary -listen 127.0.0.1:$controller_port -store $controller_store -keydir $controller_keydir" \
    "WorkingDirectory=$test_dir" \
    'Restart=on-failure' \
    'RestartSec=100ms' \
    'TimeoutStartSec=10s' \
    'TimeoutStopSec=10s' \
    'UMask=0077' \
    'NoNewPrivileges=true' \
    '' \
    '[Install]' \
    'WantedBy=multi-user.target' \
    >"$unit_path"
chmod 644 -- "$unit_path"
verify_log="$test_dir/systemd-analyze.log"
if ! systemd-analyze verify "$unit_path" >"$verify_log" 2>&1; then
    cat -- "$verify_log" >&2
    exit 1
fi
systemctl daemon-reload
systemctl enable --runtime "$unit"
systemctl is-enabled --quiet "$unit"

wait_ready() {
    local attempt
    for attempt in {1..200}; do
        if ! systemctl is-active --quiet "$unit"; then
            systemctl status "$unit" --no-pager >&2 || true
            return 1
        fi
        if curl --fail --silent --show-error --max-time 1 "http://127.0.0.1:$controller_port/readyz" >/dev/null; then
            return 0
        fi
        sleep 0.05
    done
    systemctl status "$unit" --no-pager >&2 || true
    return 1
}

systemctl start "$unit"
wait_ready
first_pid=$(systemctl show "$unit" -p MainPID --value)
[[ "$first_pid" =~ ^[1-9][0-9]*$ ]]
[[ -e "/proc/$first_pid/exe" ]]
[[ "$(readlink -f -- "/proc/$first_pid/exe")" == "$controller_binary" ]]
[[ -s "$controller_store" ]]
[[ -f "$controller_store-wal" && ! -L "$controller_store-wal" ]]
[[ -f "$controller_store-shm" && ! -L "$controller_store-shm" ]]

systemctl restart "$unit"
wait_ready
second_pid=$(systemctl show "$unit" -p MainPID --value)
[[ "$second_pid" =~ ^[1-9][0-9]*$ ]]
[[ "$second_pid" != "$first_pid" ]]
[[ "$(readlink -f -- "/proc/$second_pid/exe")" == "$controller_binary" ]]
[[ -f "$controller_store-wal" && ! -L "$controller_store-wal" ]]
[[ -f "$controller_store-shm" && ! -L "$controller_store-shm" ]]

systemctl stop "$unit"
systemctl is-active --quiet "$unit" && exit 1 || true
systemctl is-enabled --quiet "$unit"
systemctl disable --runtime "$unit"
systemctl is-enabled --quiet "$unit" && exit 1 || true
if curl --fail --silent --show-error --max-time 1 "http://127.0.0.1:$controller_port/readyz" >/dev/null 2>&1; then
    exit 1
fi

ANTINAT_P18_TEST_TMP="$test_dir/installer" bash "$script_dir/test-installers.sh" >/dev/null
printf '%s\n' 'scripts/test-systemd.sh: PASS (actual antinat-controller start/ready/restart/stop under a temporary systemd unit)'
printf '%s\n' 'scripts/test-systemd.sh: LIMITS (Agent lifecycle, native Windows, OpenRC, arm64, and real-WAN paths require their native hosts; installer purge/upgrade remains isolated-root evidence)'
