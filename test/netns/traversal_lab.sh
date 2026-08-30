#!/usr/bin/env bash
# AntiNAT P12 TCP traversal lab (test/netns).
#
# Three-namespace topology exercising the real traversal adapters against a
# real gateway daemon (miniupnpd with PCP, NAT-PMP and UPnP IGDv2) and a
# real STUN server (coturn):
#
#   agent_ns (10.0.0.2) -> cpe_ns (miniupnpd, lan0 10.0.0.1 / wan0 11.0.0.2)
#                       -> vantage_ns (11.0.0.1: coturn STUN + WAN client)
#
# Two modes:
#   ANTINAT_P12_KEEP=1  setup mode: build everything, print markers, and
#                       LEAVE it running — the owning test tears down by
#                       re-running this script with ANTINAT_P12_TEARDOWN=1.
#   ANTINAT_P12_TEARDOWN=1
#                       teardown mode: kill the printed daemon PIDs, delete
#                       the namespaces, remove the work dir.
# Without either variable the script is self-cleaning (standalone lab run).
set -euo pipefail

prefix="${ANTINAT_P12_PREFIX:-antinat-p12-$$}"
agent_ns="${prefix}-agent"
cpe_ns="${prefix}-cpe"
vantage_ns="${prefix}-vantage"
work_dir="${ANTINAT_P12_WORK_DIR:-$(mktemp -d /tmp/antinat-p12-netns.XXXXXX)}"
keep="${ANTINAT_P12_KEEP:-0}"
teardown="${ANTINAT_P12_TEARDOWN:-0}"
miniupnpd_pid="${ANTINAT_P12_MINIUPNPD_PID:-}"
turn_pid="${ANTINAT_P12_TURN_PID:-}"
suffix="$(echo "$prefix" | md5sum | cut -c1-8)"
cleaned=0

teardown_all() {
    if [[ -n "$miniupnpd_pid" ]]; then
        kill "$miniupnpd_pid" 2>/dev/null || true
        wait "$miniupnpd_pid" 2>/dev/null || true
    fi
    if [[ -n "$turn_pid" ]]; then
        kill "$turn_pid" 2>/dev/null || true
        wait "$turn_pid" 2>/dev/null || true
    fi
    for namespace in "$agent_ns" "$cpe_ns" "$vantage_ns"; do
        ip netns del "$namespace" 2>/dev/null || true
    done
    rm -f "$work_dir"/miniupnpd.* "$work_dir"/turn.* "$work_dir"/upnp.leases \
          "$work_dir"/results.jsonl "$work_dir"/results.txt "$work_dir"/done
    rmdir "$work_dir" 2>/dev/null || true
}

cleanup() {
    local status=$?
    if [[ $cleaned -eq 1 ]]; then
        return "$status"
    fi
    cleaned=1
    # Keep mode leaves the topology running ONLY on success: a setup
    # failure (readiness poll, interrupted setup) must still tear down,
    # otherwise namespaces and daemons leak (lifecycle review finding).
    if [[ "$teardown" == "1" || "$keep" != "1" || $status -ne 0 ]]; then
        teardown_all
    fi
    return "$status"
}
# EXIT is the single owner of teardown. A signal trap must exit nonzero instead
# of calling cleanup directly: with KEEP=1, cleanup would otherwise observe the
# interrupted command's status as zero, mark itself cleaned, skip teardown and
# let the eventual EXIT trap become a no-op (lifecycle review finding).
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

for command in ip nft miniupnpd turnserver; do
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

ip -n "$agent_ns" addr add 10.0.0.2/24 dev lan0
ip -n "$cpe_ns" addr add 10.0.0.1/24 dev lan0
ip -n "$cpe_ns" addr add 11.0.0.2/24 dev wan0
ip -n "$vantage_ns" addr add 11.0.0.1/24 dev lan0
for pair in "$agent_ns:lan0" "$cpe_ns:lan0" "$cpe_ns:wan0" "$vantage_ns:lan0"; do
    ip -n "${pair%%:*}" link set "${pair##*:}" up
done
ip -n "$agent_ns" route add default via 10.0.0.1
ip netns exec "$cpe_ns" sysctl -q -w net.ipv4.ip_forward=1

# CPE firewall/NAT tables for miniupnpd (nftables backend).
ip netns exec "$cpe_ns" /etc/miniupnpd/nft_init.sh -t p12filter -n p12nat >/dev/null
ip netns exec "$cpe_ns" nft add rule inet p12filter forward accept
ip netns exec "$cpe_ns" nft add rule inet p12nat postrouting oifname wan0 ip saddr 10.0.0.0/24 masquerade

cat >"$work_dir/miniupnpd.conf" <<EOF
ext_ifname=wan0
listening_ip=lan0
http_port=0
ipv6_disable=yes
enable_pcp_pmp=yes
enable_upnp=yes
secure_mode=yes
system_uptime=yes
notify_interval=5
lease_file=$work_dir/upnp.leases
uuid=9e21d2d0-3c3f-4c1a-9f21-1d1d1d1d1d1d
upnp_table_name=p12filter
upnp_nat_table_name=p12nat
upnp_forward_chain=miniupnpd
upnp_nat_chain=prerouting_miniupnpd
upnp_nat_postrouting_chain=postrouting_miniupnpd
allow 1024-65535 10.0.0.0/24 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
EOF

ip netns exec "$cpe_ns" miniupnpd -f "$work_dir/miniupnpd.conf" -d -v -P "$work_dir/miniupnpd.pid" >"$work_dir/miniupnpd.log" 2>&1 &
miniupnpd_pid=$!
ip netns exec "$vantage_ns" turnserver -n -S -L 11.0.0.1 -p 3478 --no-cli --no-tls --no-dtls \
    --pidfile "$work_dir/turn.pid" --log-file stdout >"$work_dir/turn.log" 2>&1 &
turn_pid=$!

ready=0
for _ in $(seq 1 60); do
    if kill -0 "$miniupnpd_pid" 2>/dev/null && kill -0 "$turn_pid" 2>/dev/null && \
        ip netns exec "$vantage_ns" ss -lun | grep -q '11.0.0.1:3478'; then
        ready=1
        break
    fi
    sleep 0.2
done
if [[ $ready -ne 1 ]]; then
    echo "miniupnpd log:" >&2
    cat "$work_dir/miniupnpd.log" >&2
    echo "coturn log:" >&2
    cat "$work_dir/turn.log" >&2
    exit 1
fi

# Test seam for signal-cleanup verification: announce that all resources and
# daemons exist, then wait to be interrupted before publishing READY markers.
# Production invocations leave the variable empty and never enter this block.
if [[ -n "${ANTINAT_P12_READY_HOLD_FILE:-}" ]]; then
    : >"$ANTINAT_P12_READY_HOLD_FILE"
    while true; do sleep 1; done
fi

cat <<ENVEOF
TOPOLOGY=AGENT_CPE_VANTAGE
GATEWAY_DAEMON=miniupnpd
GATEWAY=10.0.0.1
STUN=11.0.0.1:3478
CPE_WAN=11.0.0.2
VANTAGE=11.0.0.1
AGENT_NS=$agent_ns
CPE_NS=$cpe_ns
VANTAGE_NS=$vantage_ns
WORK_DIR=$work_dir
MINIUPNPD_PID=$miniupnpd_pid
TURN_PID=$turn_pid
READY=1
ENVEOF
