#!/usr/bin/env bash
# AntiNAT P13 UDP single-socket data-plane lab (test/netns).
#
# Three-namespace topology exercising the P13 UDP forwarder end to end:
#
#   agent_ns (198.51.100.2) -> cpe_ns (198.51.100.1 lan0 / 11.0.0.2 wan0)
#                           -> vantage_ns (11.0.0.1)
#
# The CPE is a plain IPv4 router (forwarding only, no NAT on the LAN path):
# an external client inside vantage_ns reaches the agent's published tuple
# 198.51.100.2:PORT through the CPE, and the agent's ingress replies return
# with source == the published tuple. The agent LAN uses RFC 5737 TEST-NET-2
# so the published tuple satisfies the production probe endpoint validator.
# Two UDP echo targets (A and B) run on the CPE LAN side
# (198.51.100.1:24001 and 198.51.100.1:24002) as the forwarder backends, so
# target hot update is exercised across real cross-namespace sockets.
#
# Modes (same lifecycle contract as the P12 traversal lab):
#   ANTINAT_P13_KEEP=1      setup mode: build everything, print markers, and
#                           LEAVE it running — the owning test tears down by
#                           re-running this script with ANTINAT_P13_TEARDOWN=1.
#   ANTINAT_P13_TEARDOWN=1  teardown mode: kill the printed daemon PIDs, delete
#                           the namespaces, remove the work dir.
# Without either variable the script is self-cleaning (standalone lab run).
set -euo pipefail

prefix="${ANTINAT_P13_PREFIX:-antinat-p13-$$}"
agent_ns="${prefix}-agent"
cpe_ns="${prefix}-cpe"
vantage_ns="${prefix}-vantage"
work_dir="${ANTINAT_P13_WORK_DIR:-$(mktemp -d /tmp/antinat-p13-netns.XXXXXX)}"
keep="${ANTINAT_P13_KEEP:-0}"
teardown="${ANTINAT_P13_TEARDOWN:-0}"
echo_a_pid="${ANTINAT_P13_ECHO_A_PID:-}"
echo_b_pid="${ANTINAT_P13_ECHO_B_PID:-}"
suffix="$(echo "$prefix" | md5sum | cut -c1-8)"
cleaned=0

# The agent LAN uses the RFC 5737 TEST-NET-2 range: the production probe
# endpoint validator requires a global/documentation IPv4 literal, so the
# forwarder's published tuple must be probe-addressable.
agent_ip=198.51.100.2
gateway_ip=198.51.100.1
cpe_wan_ip=11.0.0.2
vantage_ip=11.0.0.1
echo_a_port=24001
echo_b_port=24002

teardown_all() {
    if [[ -n "$echo_a_pid" ]]; then
        kill "$echo_a_pid" 2>/dev/null || true
        wait "$echo_a_pid" 2>/dev/null || true
    fi
    if [[ -n "$echo_b_pid" ]]; then
        kill "$echo_b_pid" 2>/dev/null || true
        wait "$echo_b_pid" 2>/dev/null || true
    fi
    for namespace in "$agent_ns" "$cpe_ns" "$vantage_ns"; do
        ip netns del "$namespace" 2>/dev/null || true
    done
    rm -rf "$work_dir"
}

cleanup() {
    local status=$?
    if [[ $cleaned -eq 1 ]]; then
        return "$status"
    fi
    cleaned=1
    # Keep mode leaves the topology running ONLY on success: a setup failure
    # (readiness poll, interrupted setup) must still tear down, otherwise
    # namespaces and daemons leak (P12 lifecycle review finding).
    if [[ "$teardown" == "1" || "$keep" != "1" || $status -ne 0 ]]; then
        teardown_all
    fi
    return "$status"
}
# EXIT is the single owner of teardown. A signal trap must exit nonzero instead
# of calling cleanup directly: with KEEP=1, cleanup would otherwise observe the
# interrupted command's status as zero, mark itself cleaned, skip teardown and
# let the eventual EXIT trap become a no-op (P12 lifecycle review finding).
on_signal() {
    local signal_status="$1"
    trap - INT TERM
    exit "$signal_status"
}
trap cleanup EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

if [[ "$teardown" == "1" ]]; then
    for command in ip; do
        command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 125; }
    done
    teardown_all
    echo "TEARDOWN=1"
    exit 0
fi

for command in ip nft bash python3; do
    command -v "$command" >/dev/null || { echo "missing prerequisite $command" >&2; exit 125; }
done

for namespace in "$agent_ns" "$cpe_ns" "$vantage_ns"; do
    ip netns add "$namespace"
    ip -n "$namespace" link set lo up
done

# agent_ns lan0 <-> cpe_ns lan0
ip link add "a${suffix}" type veth peer name "b${suffix}"
ip link set "a${suffix}" netns "$agent_ns"
ip link set "b${suffix}" netns "$cpe_ns"
ip -n "$agent_ns" link set "a${suffix}" name lan0
ip -n "$cpe_ns" link set "b${suffix}" name lan0

# cpe_ns wan0 <-> vantage_ns lan0
ip link add "c${suffix}" type veth peer name "d${suffix}"
ip link set "c${suffix}" netns "$cpe_ns"
ip link set "d${suffix}" netns "$vantage_ns"
ip -n "$cpe_ns" link set "c${suffix}" name wan0
ip -n "$vantage_ns" link set "d${suffix}" name lan0

ip -n "$agent_ns" addr add "$agent_ip/24" dev lan0
ip -n "$cpe_ns" addr add "$gateway_ip/24" dev lan0
ip -n "$cpe_ns" addr add "$cpe_wan_ip/24" dev wan0
ip -n "$vantage_ns" addr add "$vantage_ip/24" dev lan0
for pair in "$agent_ns:lan0" "$cpe_ns:lan0" "$cpe_ns:wan0" "$vantage_ns:lan0"; do
    ip -n "${pair%%:*}" link set "${pair##*:}" up
done
ip -n "$agent_ns" route add default via "$gateway_ip"
ip -n "$vantage_ns" route add 198.51.100.0/24 via "$cpe_wan_ip"
ip netns exec "$cpe_ns" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$cpe_ns" nft add table inet p13filter
ip netns exec "$cpe_ns" nft add chain inet p13filter forward '{ type filter hook forward priority filter; policy accept; }'

# UDP echo targets A and B on the CPE LAN side.
cat >"$work_dir/udp_echo.py" <<'PYEOF'
import socket
import sys


def main():
    prefix = sys.argv[1].encode()
    port = int(sys.argv[2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("198.51.100.1", port))
    while True:
        data, addr = sock.recvfrom(65535)
        reply = prefix + data
        try:
            sock.sendto(reply, addr)
        except OSError:
            # A reply beyond the 65,507-byte UDP payload maximum cannot be
            # sent; drop it without killing the server (boundary handling).
            pass


if __name__ == "__main__":
    main()
PYEOF

ip netns exec "$cpe_ns" python3 "$work_dir/udp_echo.py" "A:" "$echo_a_port" >"$work_dir/echo-a.log" 2>&1 &
echo_a_pid=$!
ip netns exec "$cpe_ns" python3 "$work_dir/udp_echo.py" "B:" "$echo_b_port" >"$work_dir/echo-b.log" 2>&1 &
echo_b_pid=$!

ready=0
for _ in $(seq 1 60); do
    if kill -0 "$echo_a_pid" 2>/dev/null && kill -0 "$echo_b_pid" 2>/dev/null && \
        ip netns exec "$cpe_ns" ss -lun | grep -q "$gateway_ip:$echo_a_port" && \
        ip netns exec "$cpe_ns" ss -lun | grep -q "$gateway_ip:$echo_b_port"; then
        ready=1
        break
    fi
    sleep 0.2
done
if [[ $ready -ne 1 ]]; then
    echo "echo A log:" >&2
    cat "$work_dir/echo-a.log" >&2
    echo "echo B log:" >&2
    cat "$work_dir/echo-b.log" >&2
    exit 1
fi

# Vantage UDP client helper used by the integration test. Sends `count`
# datagrams (one per fresh socket, default 1) from the calling namespace and
# prints each response's payload and exact source tuple, then a RESPONSES=N
# summary for burst mode. --bind-port N pins the source port (N..N+count-1)
# so distinct client tuples can be expressed deterministically: the kernel's
# ephemeral allocator would otherwise reuse one port for identical
# local/remote pairs and collapse distinct clients into one forwarder session.
cat >"$work_dir/udp_client.py" <<'PYEOF'
import base64
import socket
import sys


def recv_one(sock, timeout_ms):
    sock.settimeout(timeout_ms / 1000.0)
    try:
        data, addr = sock.recvfrom(65535)
        return data, addr
    except socket.timeout:
        return None, None


def main():
    args = sys.argv[1:]
    bind_base = None
    rest = []
    i = 0
    while i < len(args):
        if args[i] == "--bind-port":
            bind_base = int(args[i + 1])
            i += 2
        elif args[i] == "--burst":
            rest.append(args[i])
            i += 1
        else:
            rest.append(args[i])
            i += 1
    args = rest
    if args and args[0] == "--burst":
        _, endpoint, payload_b64, count, timeout_ms = args
        count = int(count)
    else:
        endpoint, payload_b64, timeout_ms = args
        count = 1
    host, port = endpoint.rsplit(":", 1)
    payload = base64.b64decode(payload_b64)
    socks = []
    for i in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if bind_base is not None:
            sock.bind(("11.0.0.1", bind_base + i))
        sock.sendto(payload, (host, int(port)))
        socks.append(sock)
    responses = 0
    for sock in socks:
        data, addr = recv_one(sock, int(timeout_ms))
        if data is not None:
            responses += 1
            print("RESP=%s FROM=%s:%s" % (
                base64.b64encode(data).decode(), addr[0], addr[1]))
        sock.close()
    if count > 1:
        print("RESPONSES=%d" % responses)


if __name__ == "__main__":
    main()
PYEOF

# Test seam for signal-cleanup verification: announce that all resources and
# daemons exist, then wait to be interrupted before publishing READY markers.
# Production invocations leave the variable empty and never enter this block.
if [[ -n "${ANTINAT_P13_READY_HOLD_FILE:-}" ]]; then
    : >"$ANTINAT_P13_READY_HOLD_FILE"
    while true; do sleep 1; done
fi

cat <<ENVEOF
TOPOLOGY=AGENT_CPE_VANTAGE
AGENT=$agent_ip
GATEWAY=$gateway_ip
CPE_WAN=$cpe_wan_ip
VANTAGE=$vantage_ip
ECHO_A=$gateway_ip:$echo_a_port
ECHO_B=$gateway_ip:$echo_b_port
AGENT_NS=$agent_ns
CPE_NS=$cpe_ns
VANTAGE_NS=$vantage_ns
WORK_DIR=$work_dir
ECHO_A_PID=$echo_a_pid
ECHO_B_PID=$echo_b_pid
READY=1
ENVEOF
