#!/usr/bin/env bash
set -euo pipefail

prefix="antinat-p02-$$"
agent_ns="${prefix}-agent"
cpe_ns="${prefix}-cpe"
cgn_ns="${prefix}-cgn"
vantage_ns="${prefix}-vantage"
work_dir="$(mktemp -d /tmp/antinat-p02-netns.XXXXXX)"
miniupnpd_pid=""
turn_pid=""
cleaned=0

cleanup() {
    local status=$?
    if [[ $cleaned -eq 1 ]]; then
        return "$status"
    fi
    cleaned=1
    if [[ -n "$miniupnpd_pid" ]]; then
        kill "$miniupnpd_pid" 2>/dev/null || true
        wait "$miniupnpd_pid" 2>/dev/null || true
    fi
    if [[ -n "$turn_pid" ]]; then
        kill "$turn_pid" 2>/dev/null || true
        wait "$turn_pid" 2>/dev/null || true
    fi
    for namespace in "$agent_ns" "$cpe_ns" "$cgn_ns" "$vantage_ns"; do
        ip netns del "$namespace" 2>/dev/null || true
    done
    rm -f "$work_dir/miniupnpd.conf" "$work_dir/miniupnpd.log" "$work_dir/miniupnpd.pid" \
        "$work_dir/turn.log" "$work_dir/turn.pid" "$work_dir/upnpc-add.log" \
        "$work_dir/upnpc-list.log" "$work_dir/upnpc-delete.log" "$work_dir/stun.log"
    rmdir "$work_dir" 2>/dev/null || true
    return "$status"
}
trap cleanup EXIT INT TERM

for command in ip nft miniupnpd upnpc turnserver turnutils_stunclient; do
    command -v "$command" >/dev/null
 done

for namespace in "$agent_ns" "$cpe_ns" "$cgn_ns" "$vantage_ns"; do
    ip netns add "$namespace"
    ip -n "$namespace" link set lo up
 done

suffix="$$"
ip link add "a${suffix}" type veth peer name "b${suffix}"
ip link set "a${suffix}" netns "$agent_ns"
ip link set "b${suffix}" netns "$cpe_ns"
ip -n "$agent_ns" link set "a${suffix}" name lan0
ip -n "$cpe_ns" link set "b${suffix}" name lan0

ip link add "c${suffix}" type veth peer name "d${suffix}"
ip link set "c${suffix}" netns "$cpe_ns"
ip link set "d${suffix}" netns "$cgn_ns"
ip -n "$cpe_ns" link set "c${suffix}" name wan0
ip -n "$cgn_ns" link set "d${suffix}" name lan0

ip link add "e${suffix}" type veth peer name "f${suffix}"
ip link set "e${suffix}" netns "$cgn_ns"
ip link set "f${suffix}" netns "$vantage_ns"
ip -n "$cgn_ns" link set "e${suffix}" name wan0
ip -n "$vantage_ns" link set "f${suffix}" name lan0

ip -n "$agent_ns" addr add 10.0.0.2/24 dev lan0
ip -n "$cpe_ns" addr add 10.0.0.1/24 dev lan0
ip -n "$cpe_ns" addr add 100.64.0.2/24 dev wan0
ip -n "$cgn_ns" addr add 100.64.0.1/24 dev lan0
ip -n "$cgn_ns" addr add 11.0.0.2/24 dev wan0
ip -n "$vantage_ns" addr add 11.0.0.1/24 dev lan0
for pair in "$agent_ns:lan0" "$cpe_ns:lan0" "$cpe_ns:wan0" "$cgn_ns:lan0" "$cgn_ns:wan0" "$vantage_ns:lan0"; do
    ip -n "${pair%%:*}" link set "${pair##*:}" up
 done
ip -n "$agent_ns" route add default via 10.0.0.1
ip -n "$cpe_ns" route add default via 100.64.0.1
ip -n "$cgn_ns" route add default via 11.0.0.1
ip netns exec "$cpe_ns" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$cgn_ns" sysctl -q -w net.ipv4.ip_forward=1

ip netns exec "$cpe_ns" /etc/miniupnpd/nft_init.sh -t p02filter -n p02nat >/dev/null
ip netns exec "$cpe_ns" nft add rule inet p02filter forward accept
ip netns exec "$cpe_ns" nft add rule inet p02nat postrouting oifname wan0 ip saddr 10.0.0.0/24 masquerade
ip netns exec "$cgn_ns" nft add table ip p02nat
ip netns exec "$cgn_ns" nft 'add chain ip p02nat postrouting { type nat hook postrouting priority 100; policy accept; }'
ip netns exec "$cgn_ns" nft add rule ip p02nat postrouting oifname wan0 ip saddr 100.64.0.0/24 masquerade

cat >"$work_dir/miniupnpd.conf" <<EOF
ext_ifname=wan0
ext_perform_stun=yes
ext_stun_host=11.0.0.1
ext_stun_port=3478
listening_ip=lan0
http_port=0
ipv6_disable=yes
enable_pcp_pmp=yes
enable_upnp=yes
secure_mode=yes
system_uptime=yes
notify_interval=15
lease_file=$work_dir/upnp.leases
uuid=2d80bf22-7b52-4e03-a76d-9b742e6df2a2
upnp_table_name=p02filter
upnp_nat_table_name=p02nat
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
for _ in $(seq 1 40); do
    if kill -0 "$miniupnpd_pid" 2>/dev/null && kill -0 "$turn_pid" 2>/dev/null && \
        ip netns exec "$vantage_ns" ss -lun | grep -q '11.0.0.1:3478'; then
        ready=1
        break
    fi
    sleep 0.1
 done
if [[ $ready -ne 1 ]]; then
    echo "miniupnpd log:" >&2
    cat "$work_dir/miniupnpd.log" >&2
    echo "coturn log:" >&2
    cat "$work_dir/turn.log" >&2
    exit 1
fi

set +e
ip netns exec "$agent_ns" upnpc -m lan0 -e AntiNAT-P02 -a 10.0.0.2 3111 43111 TCP 120 >"$work_dir/upnpc-add.log" 2>&1
upnpc_status=$?
set -e
if [[ $upnpc_status -eq 0 ]]; then
    echo "layered mapping unexpectedly succeeded through restrictive CGN" >&2
    exit 1
fi
ip netns exec "$agent_ns" upnpc -m lan0 -l >"$work_dir/upnpc-list.log" 2>&1
grep -q '11.0.0.2' "$work_dir/upnpc-add.log"
grep -q 'failed with code 501' "$work_dir/upnpc-add.log"
grep -q 'behind restrictive or symmetric NAT' "$work_dir/miniupnpd.log"
grep -q 'Port forwarding is now disabled' "$work_dir/miniupnpd.log"
if grep -q '43111.*TCP.*10.0.0.2:3111' "$work_dir/upnpc-list.log"; then
    echo "failed layered mapping was retained" >&2
    exit 1
fi

ip netns exec "$agent_ns" turnutils_stunclient -L 10.0.0.2 -p 3478 11.0.0.1 >"$work_dir/stun.log" 2>&1
grep -Eq '11\.0\.0\.2:[0-9]+' "$work_dir/stun.log"
observed="$(grep -Eo '11\.0\.0\.2:[0-9]+' "$work_dir/stun.log" | head -n1)"

echo "TOPOLOGY=CPE_TO_CGN"
echo "UPNP_DAEMON=miniupnpd"
echo "UPNP_MAPPING=BLOCKED_RESTRICTIVE_CGN"
echo "UPSTREAM_STUN=coturn"
echo "FIRST_HOP=100.64.0.2"
echo "STUN_OBSERVED=$observed"
echo "LAYERED_ENDPOINTS_DIFFER=PASS"
