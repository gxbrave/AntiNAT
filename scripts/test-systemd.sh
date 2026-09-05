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
native_stage="$test_dir/native-stage"
native_started=0
native_finished=0
native_tls_pid=
native_agent_dropin=/etc/systemd/system/antinat-agent.service.d/p18-native-test.conf
cleanup() {
    local original_status=$? cleanup_failed=0 native_path
    trap - EXIT
    set +e
    systemctl stop "$unit" >/dev/null 2>&1 || true
    systemctl disable --runtime "$unit" >/dev/null 2>&1 || true
    rm -f -- "$unit_path"
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [[ "$native_started" == 1 && "$native_finished" != 1 && -x "$native_stage/scripts/install.sh" ]]; then
        ANTINAT_ROLE=both ANTINAT_FORCE_OFFLINE_PURGE=1 \
            bash "$native_stage/scripts/install.sh" purge >/dev/null 2>&1 || true
    fi
    if [[ "$native_started" == 1 ]]; then
        systemctl disable --now antinat-agent.service antinat-controller.service >/dev/null 2>&1 || true
        systemctl daemon-reload >/dev/null 2>&1 || true
        if [[ ! -e /opt/antinat && ! -e /var/lib/antinat && ! -e /var/log/antinat && ! -e /etc/antinat ]]; then
            userdel antinat >/dev/null 2>&1 || true
            groupdel antinat >/dev/null 2>&1 || true
        fi
    fi
    if [[ -n "${native_tls_pid:-}" ]]; then
        kill "$native_tls_pid" >/dev/null 2>&1 || true
        wait "$native_tls_pid" >/dev/null 2>&1 || true
    fi
    rm -f -- "$native_agent_dropin"
    rmdir -- "$(dirname -- "$native_agent_dropin")" 2>/dev/null || true
    if [[ "$native_started" == 1 ]]; then
        for native_path in \
            /opt/antinat /var/lib/antinat /var/log/antinat /etc/antinat \
            /etc/systemd/system/antinat-agent.service \
            /etc/systemd/system/antinat-controller.service \
            "$native_agent_dropin"; do
            if [[ -e "$native_path" || -L "$native_path" ]]; then
                printf 'scripts/test-systemd.sh: cleanup left %s\n' "$native_path" >&2
                cleanup_failed=1
            fi
        done
        if id antinat >/dev/null 2>&1 || getent group antinat >/dev/null 2>&1; then
            printf '%s\n' 'scripts/test-systemd.sh: cleanup left the antinat account' >&2
            cleanup_failed=1
        fi
    fi
    rm -rf -- "$test_dir"
    if ((cleanup_failed != 0)); then
        exit 1
    fi
    exit "$original_status"
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

# Exercise the shipped installer and units against the host's real systemd.
# Refuse to run when any production-shaped resource already exists; this lane
# is destructive only to the pristine resources it creates below.
for native_path in \
    /opt/antinat /var/lib/antinat /var/log/antinat /etc/antinat \
    /etc/systemd/system/antinat-agent.service \
    /etc/systemd/system/antinat-controller.service \
    "$native_agent_dropin"; do
    if [[ -e "$native_path" || -L "$native_path" ]]; then
        printf 'scripts/test-systemd.sh: refusing native lifecycle test; %s already exists\n' "$native_path" >&2
        exit 1
    fi
done
if id antinat >/dev/null 2>&1 || getent group antinat >/dev/null 2>&1; then
    printf '%s\n' 'scripts/test-systemd.sh: refusing native lifecycle test; antinat account already exists' >&2
    exit 1
fi

mkdir -p -- "$native_stage/scripts" "$native_stage/deploy/trust" "$native_stage/deploy/systemd"
cp -a -- "$repo_dir/scripts/." "$native_stage/scripts/"
cp -a -- "$repo_dir/deploy/systemd/." "$native_stage/deploy/systemd/"
native_release="$test_dir/native-release"
mkdir -p -- "$native_release"
chmod 700 -- "$native_release"
native_key="$test_dir/native-release.key"
openssl genpkey -algorithm Ed25519 -out "$native_key" 2>/dev/null
openssl pkey -in "$native_key" -pubout -out "$native_stage/deploy/trust/release-ed25519.pub" 2>/dev/null

make_native_release() {
    local version="$1" digest_agent digest_controller digest_hook
    local ldflags="-X github.com/gxbrave/AntiNAT/internal/buildinfo.Version=$version -X github.com/gxbrave/AntiNAT/internal/buildinfo.Commit=$(git -C "$repo_dir" rev-parse HEAD) -X github.com/gxbrave/AntiNAT/internal/buildinfo.Date=2026-09-05T00:00:00Z"
    GOWORK=off go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$native_release/antinat-agent-linux-amd64" "$repo_dir/cmd/antinat-agent"
    GOWORK=off go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$native_release/antinat-controller-linux-amd64" "$repo_dir/cmd/antinat-controller"
    GOWORK=off go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$native_release/antinat-hook-runner-linux-amd64" "$repo_dir/cmd/antinat-hook-runner"
    digest_agent=$(sha256sum "$native_release/antinat-agent-linux-amd64" | awk '{print $1}')
    digest_controller=$(sha256sum "$native_release/antinat-controller-linux-amd64" | awk '{print $1}')
    digest_hook=$(sha256sum "$native_release/antinat-hook-runner-linux-amd64" | awk '{print $1}')
    jq -cn --arg release "$version" --arg agent "$digest_agent" --arg controller "$digest_controller" --arg hook "$digest_hook" \
        '{schema_version:1,release:$release,artifacts:{"antinat-agent-linux-amd64":$agent,"antinat-controller-linux-amd64":$controller,"antinat-hook-runner-linux-amd64":$hook},trust_root:"release-key-2026",signature_algorithm:"ed25519"}' \
        >"$native_release/manifest.json"
    openssl pkeyutl -sign -rawin -inkey "$native_key" -in "$native_release/manifest.json" -out "$native_release/manifest.sig" 2>/dev/null
}

wait_native_ready() {
    local service="$1" url="$2" attempt
    for attempt in {1..200}; do
        if systemctl is-active --quiet "$service" && curl --fail --silent --show-error --max-time 1 "$url" >/dev/null; then
            return 0
        fi
        sleep 0.05
    done
    systemctl status "$service" --no-pager >&2 || true
    return 1
}

make_native_release p18-old
native_started=1
ANTINAT_ROLE=controller ANTINAT_ARTIFACT_DIR="$native_release" \
    bash "$native_stage/scripts/install.sh" install >/dev/null
wait_native_ready antinat-controller.service http://127.0.0.1:3111/readyz
[[ "$(readlink -f /proc/$(systemctl show antinat-controller.service -p MainPID --value)/exe)" == /opt/antinat/bin/antinat-controller ]]

# Keep the production HTTPS requirement intact while exercising the local
# Controller. A temporary TLS bridge presents a test CA that is mounted
# read-only into only the Agent service.
native_tls_cert="$test_dir/native-tls-cert.pem"
native_tls_key="$test_dir/native-tls-key.pem"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' \
    -keyout "$native_tls_key" -out "$native_tls_cert" >/dev/null 2>&1
native_tls_source="$test_dir/tls-bridge.go"
cat >"$native_tls_source" <<'GO'
package main

import (
	"crypto/tls"
	"io"
	"net"
	"os"
)

func main() {
	certificate, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil { panic(err) }
	listener, err := tls.Listen("tcp", "127.0.0.1:3443", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil { panic(err) }
	for {
		client, err := listener.Accept()
		if err != nil { return }
		go func() {
			defer client.Close()
			backend, err := net.Dial("tcp", "127.0.0.1:3111")
			if err != nil { return }
			defer backend.Close()
			done := make(chan struct{}, 1)
			go func() { _, _ = io.Copy(backend, client); done <- struct{}{} }()
			go func() { _, _ = io.Copy(client, backend); done <- struct{}{} }()
			<-done
		}()
	}
}
GO
native_tls_bridge="$test_dir/tls-bridge"
GOWORK=off go build -trimpath -buildvcs=false -o "$native_tls_bridge" "$native_tls_source"
"$native_tls_bridge" "$native_tls_cert" "$native_tls_key" &
native_tls_pid=$!
mkdir -p -- "$(dirname -- "$native_agent_dropin")"
cat >"$native_agent_dropin" <<EOF
[Service]
Environment=SSL_CERT_FILE=/run/antinat-p18-native-ca.pem
BindReadOnlyPaths=$native_tls_cert:/run/antinat-p18-native-ca.pem
EOF
systemctl daemon-reload
for _ in {1..100}; do
    curl --fail --silent --show-error --cacert "$native_tls_cert" https://127.0.0.1:3443/readyz >/dev/null 2>&1 && break
    sleep 0.05
done
curl --fail --silent --show-error --cacert "$native_tls_cert" https://127.0.0.1:3443/readyz >/dev/null

native_ctl="$test_dir/antinatctl"
GOWORK=off go build -trimpath -buildvcs=false -o "$native_ctl" "$repo_dir/cmd/antinatctl"
native_password="$test_dir/admin-password"
printf '%s\n' 'P18-native-systemd-password-9f4f6e3b' >"$native_password"
chmod 600 -- "$native_password"
native_ctl_state="$test_dir/ctl-state"
"$native_ctl" --endpoint http://127.0.0.1:3111 --state "$native_ctl_state" admin init --username p18-systemd --password-file "$native_password" >/dev/null
"$native_ctl" --endpoint http://127.0.0.1:3111 --state "$native_ctl_state" login --username p18-systemd --password-file "$native_password" >/dev/null
node_json=$("$native_ctl" --endpoint http://127.0.0.1:3111 --state "$native_ctl_state" node create --name p18-systemd-node)
node_id=$(jq -er '.id' <<<"$node_json")
cookie_header=$(paste -sd ';' "$native_ctl_state/session")
token_json=$(curl --fail --silent --show-error --max-time 10 -H "Cookie: $cookie_header" -X POST "http://127.0.0.1:3111/api/v1/nodes/$node_id/enrollment-token")
controller_pin=$(jq -er '.controller_pin | select(test("^[0-9a-f]{64}$"))' <<<"$token_json")
native_token="$test_dir/enrollment-token"
jq -er '.token' <<<"$token_json" >"$native_token"
chmod 600 -- "$native_token"
ANTINAT_ROLE=agent ANTINAT_ARTIFACT_DIR="$native_release" ANTINAT_CONTROLLER_PIN="$controller_pin" ANTINAT_NODE_ID="$node_id" \
    bash "$native_stage/scripts/install.sh" install --controller-endpoint https://127.0.0.1:3443 --platform linux --token-file "$native_token" >/dev/null
wait_native_ready antinat-controller.service http://127.0.0.1:3111/readyz
systemctl is-active --quiet antinat-agent.service
[[ ! -e "$native_token" ]]

systemctl restart antinat-controller.service
wait_native_ready antinat-controller.service http://127.0.0.1:3111/readyz
systemctl reset-failed antinat-agent.service
systemctl restart antinat-agent.service
for _ in {1..200}; do
    systemctl is-active --quiet antinat-agent.service && [[ -S /var/lib/antinat/uninstall.sock ]] && break
    sleep 0.05
done
systemctl is-active --quiet antinat-agent.service
[[ -S /var/lib/antinat/uninstall.sock ]]
old_controller_version=$(/opt/antinat/bin/antinat-controller version)
old_agent_version=$(/opt/antinat/bin/antinat-agent version)
[[ "$old_controller_version" == *'version=p18-old'* && "$old_agent_version" == *'version=p18-old'* ]]

make_native_release p18-new
set +e
ANTINAT_ROLE=both ANTINAT_ARTIFACT_DIR="$native_release" ANTINAT_FORCE_HEALTH_FAIL=1 \
    bash "$native_stage/scripts/install.sh" upgrade >/dev/null 2>&1
rollback_status=$?
set -e
[[ "$rollback_status" == 6 ]]
wait_native_ready antinat-controller.service http://127.0.0.1:3111/readyz
systemctl is-active --quiet antinat-agent.service
[[ "$(/opt/antinat/bin/antinat-controller version)" == "$old_controller_version" ]]
[[ "$(/opt/antinat/bin/antinat-agent version)" == "$old_agent_version" ]]
if [[ "${ANTINAT_P18_TEST_ABORT_AFTER_ROLLBACK:-0}" == 1 ]]; then
    exit 99
fi

ANTINAT_ROLE=both ANTINAT_ARTIFACT_DIR="$native_release" \
    bash "$native_stage/scripts/install.sh" upgrade >/dev/null
wait_native_ready antinat-controller.service http://127.0.0.1:3111/readyz
systemctl is-active --quiet antinat-agent.service
[[ "$(/opt/antinat/bin/antinat-controller version)" == *'version=p18-new'* ]]
[[ "$(/opt/antinat/bin/antinat-agent version)" == *'version=p18-new'* ]]

set +e
ANTINAT_ROLE=both bash "$native_stage/scripts/install.sh" purge >/dev/null
purge_status=$?
set -e
[[ "$purge_status" == 7 ]]
for native_path in \
    /opt/antinat /var/lib/antinat /var/log/antinat /etc/antinat \
    /etc/systemd/system/antinat-agent.service \
    /etc/systemd/system/antinat-controller.service; do
    [[ ! -e "$native_path" && ! -L "$native_path" ]]
done
systemctl is-active --quiet antinat-agent.service && exit 1 || true
systemctl is-active --quiet antinat-controller.service && exit 1 || true
native_finished=1
userdel antinat
if getent group antinat >/dev/null 2>&1; then
    groupdel antinat
fi
rm -f -- "$native_agent_dropin"
rmdir -- "$(dirname -- "$native_agent_dropin")" 2>/dev/null || true
systemctl daemon-reload

ANTINAT_P18_TEST_TMP="$test_dir/installer" bash "$script_dir/test-installers.sh" >/dev/null
printf '%s\n' 'scripts/test-systemd.sh: PASS (shipped signed installer + real systemd Controller/Agent install, enrollment, restart, failed-upgrade rollback, successful upgrade, purge, and no-residue checks)'
printf '%s\n' 'scripts/test-systemd.sh: LIMITS (native Windows, OpenRC, arm64, and real-WAN paths require their native hosts)'
