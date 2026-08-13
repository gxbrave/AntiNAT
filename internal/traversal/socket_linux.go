//go:build linux

package traversal

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// HostRouteTable reads the live Linux IPv4 routing table and interface
// addresses. /proc/net/route is IPv4-only and needs no privileges.
type HostRouteTable struct{}

// DefaultRouteV4 returns the lowest-metric IPv4 default route (ties broken
// by interface name for determinism).
func (HostRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}, "", false, err
	}
	return parseProcNetRoute(data)
}

// IPv4Addresses lists the IPv4 addresses of up, non-loopback interfaces.
func (HostRouteTable) IPv4Addresses() ([]IPv4Address, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []IPv4Address
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("traversal: read addresses of interface %s: %w", iface.Name, err)
		}
		for _, address := range addrs {
			ipNet, ok := address.(*net.IPNet)
			if !ok {
				continue
			}
			parsed, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok || !parsed.Is4() {
				continue
			}
			out = append(out, IPv4Address{Interface: iface.Name, Addr: parsed.Unmap()})
		}
	}
	return out, nil
}

type procRouteLine struct {
	iface   string
	gateway netip.Addr
	metric  int
}

// parseProcNetRoute parses /proc/net/route and returns the best IPv4 default
// route (Destination 0.0.0.0 with mask 0.0.0.0). Addresses are 8-hex-digit
// little-endian.
func parseProcNetRoute(data []byte) (netip.Addr, string, bool, error) {
	var best *procRouteLine
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		text := scanner.Text()
		if lineNumber == 1 && strings.HasPrefix(text, "Iface") {
			continue // header row
		}
		fields := strings.Fields(text)
		if len(fields) < 8 {
			return netip.Addr{}, "", false, fmt.Errorf("traversal: /proc/net/route line %d has %d fields, want >= 8", lineNumber, len(fields))
		}
		destination, err := parseHexIP(fields[1])
		if err != nil {
			return netip.Addr{}, "", false, fmt.Errorf("traversal: /proc/net/route line %d destination: %w", lineNumber, err)
		}
		mask, err := parseHexIP(fields[7])
		if err != nil {
			return netip.Addr{}, "", false, fmt.Errorf("traversal: /proc/net/route line %d mask: %w", lineNumber, err)
		}
		if !destination.IsUnspecified() || !mask.IsUnspecified() {
			continue // not a default route
		}
		gateway, err := parseHexIP(fields[2])
		if err != nil {
			return netip.Addr{}, "", false, fmt.Errorf("traversal: /proc/net/route line %d gateway: %w", lineNumber, err)
		}
		metric, err := strconv.Atoi(fields[6])
		if err != nil {
			return netip.Addr{}, "", false, fmt.Errorf("traversal: /proc/net/route line %d metric: %w", lineNumber, err)
		}
		candidate := procRouteLine{iface: fields[0], gateway: gateway, metric: metric}
		if best == nil || candidate.metric < best.metric ||
			(candidate.metric == best.metric && candidate.iface < best.iface) {
			best = &candidate
		}
	}
	if err := scanner.Err(); err != nil {
		return netip.Addr{}, "", false, err
	}
	if best == nil {
		return netip.Addr{}, "", false, nil
	}
	return best.gateway, best.iface, true, nil
}

// parseHexIP parses an 8-hex-digit little-endian IPv4 as printed by
// /proc/net/route (e.g. "0102A8C0" is 192.168.2.1).
func parseHexIP(text string) (netip.Addr, error) {
	if len(text) != 8 {
		return netip.Addr{}, fmt.Errorf("%q is not an 8-hex-digit address", text)
	}
	var octets [4]byte
	for i := 0; i < 4; i++ {
		value, err := strconv.ParseUint(text[i*2:i*2+2], 16, 8)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("%q: %w", text, err)
		}
		octets[3-i] = byte(value)
	}
	return netip.AddrFrom4(octets), nil
}
