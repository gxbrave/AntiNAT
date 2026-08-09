#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"
evidence_dir="test/evidence/m0/network"
raw_dir="$evidence_dir/raw"
mkdir -p "$raw_dir"
commit_sha="$(git rev-parse HEAD)"
windows_binary="/tmp/antinat-p02-network-$$.test.exe"
trap 'rm -f "$windows_binary"' EXIT INT TERM

write_record() {
    local filename=$1 result=$2 command=$3 timeout_seconds=$4 started=$5 finished=$6 os_name=$7 summary=$8 raw_path=$9
    shift 9
    python3 - "$evidence_dir/$filename" "$result" "$command" "$timeout_seconds" "$started" "$finished" "$os_name" "$summary" "$raw_path" "$commit_sha" "$@" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

(output, result, command, timeout_seconds, started, finished, os_name,
 summary, raw_path, commit_sha, *extra_paths) = sys.argv[1:]
raw = Path(raw_path)
record = {
    "schema_version": "antinat.evidence/v1",
    "plan": "P02",
    "commit_sha": commit_sha,
    "command": command,
    "result": result,
    "artifact_digest": "sha256:" + hashlib.sha256(raw.read_bytes()).hexdigest(),
    "os": os_name,
    "timeout": int(timeout_seconds),
    "started_at": started,
    "finished_at": finished,
    "summary": summary,
    "evidence_paths": [raw_path, "test/evidence/m0/network/environment.json", *extra_paths],
}
Path(output).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
PY
}

run_evidence() {
    local filename=$1 record=$2 result=$3 timeout_seconds=$4 os_name=$5 summary=$6 command=$7
    shift 7
    local raw_path="$raw_dir/$filename"
    local started finished status
    started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    set +e
    timeout --signal=TERM "${timeout_seconds}s" bash -lc "$command" >"$raw_path" 2>&1
    status=$?
    set -e
    finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '\nexit_code=%d\n' "$status" >>"$raw_path"
    if [[ $status -ne 0 ]]; then
        cat "$raw_path" >&2
        return "$status"
    fi
    write_record "$record" "$result" "$command" "$timeout_seconds" "$started" "$finished" "$os_name" "$summary" "$raw_path" "$@"
}

python3 - "$evidence_dir/environment.json" "$commit_sha" <<'PY'
import json
import platform
from pathlib import Path
import subprocess
import sys


def output(*command):
    return subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.strip()

record = {
    "plan": "P02",
    "commit_sha": sys.argv[2],
    "owner": "sub-agent-sol",
    "approver": "PENDING_INDEPENDENT_REVIEW",
    "os": platform.platform(),
    "kernel": platform.release(),
    "arch": platform.machine(),
    "go": output("go", "version"),
    "miniupnpd": output("miniupnpd", "--version"),
    "coturn": output("turnserver", "--version"),
    "packages": output("dpkg-query", "-W", "-f=${Package}=${Version}\\n", "miniupnpd", "miniupnpd-nftables", "miniupnpc", "coturn"),
    "router_inventory": [],
    "native_windows_host": None,
    "remote_wan_vantage": None,
    "lab_topology": "four Linux network namespaces: Agent -> CPE miniupnpd -> restrictive CGN -> coturn STUN vantage",
    "cleanup_contract": "all namespaces and daemon processes are removed by an EXIT/INT/TERM trap",
}
Path(sys.argv[1]).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
PY

run_evidence \
    tcp-linux.log tcp-shared-port-linux.json PASS 60 "linux/amd64 native" \
    "Linux unique listener plus three connected sockets shared one local tuple with deterministic four-tuple routing; baseline conflict, half-close, and exact close/rebind assertions passed." \
    "go test ./spike/network -run '^TestTCP(Baseline|SharedPort)' -count=1 -v" \
    spike/network/tcp_shared_linux.go spike/network/tcp_shared_linux_test.go

windows_started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
windows_command="GOOS=windows GOARCH=amd64 go test -c -o <temporary>/network.test.exe ./spike/network"
set +e
GOOS=windows GOARCH=amd64 go test -c -o "$windows_binary" ./spike/network >"$raw_dir/tcp-windows-cross-build.log" 2>&1
windows_status=$?
set -e
if [[ $windows_status -eq 0 ]]; then
    stat -c 'cross_build_bytes=%s' "$windows_binary" >>"$raw_dir/tcp-windows-cross-build.log"
    sha256sum "$windows_binary" >>"$raw_dir/tcp-windows-cross-build.log"
fi
echo "native_execution=false" >>"$raw_dir/tcp-windows-cross-build.log"
echo "native_windows_host=unavailable" >>"$raw_dir/tcp-windows-cross-build.log"
echo "exit_code=$windows_status" >>"$raw_dir/tcp-windows-cross-build.log"
windows_finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [[ $windows_status -ne 0 ]]; then
    cat "$raw_dir/tcp-windows-cross-build.log" >&2
    exit "$windows_status"
fi
write_record tcp-shared-port-windows.json SUPPORTED_WITH_LIMITS "$windows_command" 120 "$windows_started" "$windows_finished" \
    "windows/amd64 cross-build on linux/amd64; native runtime unavailable" \
    "Windows baseline and UDP native gates cross-compile, but no native Winsock execution exists; disable stun-tcp-shared-port and Windows UDP promotion until native evidence passes." \
    "$raw_dir/tcp-windows-cross-build.log" spike/network/tcp_shared_windows_test.go spike/network/udp_socket_windows_test.go

run_evidence \
    port-registry.log port-registry.json SUPPORTED_WITH_LIMITS 60 "linux/amd64 native" \
    "Linux socket-owning acquire, port 0, wildcard overlap, stale release, concurrent owner, reuse-group interference, and process lock assertions passed; no native Windows process-lock evidence exists." \
    "go test ./spike/network -run '^(TestPortRegistry|TestBindProbeClose|TestProcessLockBlocks|TestSecondProcess)' -count=1 -v" \
    spike/network/port_registry_linux.go spike/network/process_lock_linux.go

run_evidence \
    udp-linux.log udp-single-socket.json SUPPORTED_WITH_LIMITS 60 "linux/amd64 native" \
    "Linux one-socket STUN/probe/data demux, bounded sessions, exact-source target reply, replay rejection, truncation survival, and post-ICMP receive assertions passed; native Windows SIO_UDP_CONNRESET gate is pending." \
    "go test ./spike/network -run '^(TestUDPDemux|TestSingleUDPSocket)' -count=1 -v" \
    spike/network/udp_demux.go spike/network/udp_socket_linux.go spike/network/udp_socket_windows_test.go

run_evidence \
    hidden-challenge.log hidden-challenge.json PASS 60 "linux/amd64 native localhost transport fixture" \
    "Arm/armed, provider-hidden challenge, Ed25519 WAN frame, same-path TCP/UDP ACK, signed control receipt, replay/TTL/binding rejection, generic scanner result, and attempt budget assertions passed." \
    "go test ./spike/network -run '^(TestHiddenChallenge|TestControlOnly)' -count=1 -v" \
    spike/network/hidden_probe.go spike/network/hidden_probe_test.go

run_evidence \
    mapping-ownership.log mapping-ownership.json SUPPORTED_WITH_LIMITS 60 "platform-independent fixture on linux/amd64" \
    "FIRST_HOP publication guard, NAT-PMP port-zero delete rejection, exact UPnP query-before-delete match, and protocol-specific ownership assertions passed; no real CPE delete was attempted." \
    "go test ./spike/network -run '^(TestFirstHop|TestNATPMP|TestUPnP|TestMappingOwnership)' -count=1 -v" \
    spike/network/mapping_ownership.go spike/network/mapping_ownership_test.go

run_evidence \
    layered-nat.log layered-nat.json NO_GO 90 "linux/amd64 netns; miniupnpd 2.3.4; coturn 4.6.1" \
    "Real miniupnpd plus coturn in Agent-CPE-CGN-vantage namespaces observed distinct first-hop and upstream tuples; restrictive/symmetric CGN correctly blocked UPnP publication. Fallback: retain tested single explicit layer only and never verify FIRST_HOP_MAPPED." \
    "go test -tags=netns ./spike/network -run '^TestLayeredNATWithRealUPnPDaemonAndUpstreamSTUN$' -count=1 -v" \
    spike/network/scripts/layered_nat_lab.sh spike/network/layered_nat_netns_test.go

run_evidence \
    full-network.log full-network.json SUPPORTED_WITH_LIMITS 120 "linux/amd64 native" \
    "All non-privileged P02 network spike tests passed together; platform and real-CPE limits remain classified by individual records." \
    "go test ./spike/network/... -count=1 -v" \
    spike/network

run_evidence \
    full-network-netns.log full-network-netns.json SUPPORTED_WITH_LIMITS 180 "linux/amd64 privileged netns" \
    "All P02 network spike tests, including the real miniupnpd/coturn layered-NAT lab, passed their asserted PASS/NO_GO classifications and cleanup checks." \
    "go test -tags=netns ./spike/network/... -count=1 -v" \
    spike/network

printf 'collected P02 evidence at commit %s\n' "$commit_sha"
