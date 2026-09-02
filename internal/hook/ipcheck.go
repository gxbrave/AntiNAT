package hook

import (
	"errors"
	"net/netip"
	"strings"
)

// SSRF address validation. Every A/AAAA record of a webhook hostname must be a
// global, routable address; if ANY record is private/loopback/link-local/
// multicast/CGNAT/ULA/mapped/reserved/metadata the whole host is rejected
// (v0.8 §8.2: "校验全部 A/AAAA，任一受限地址即拒绝").
var (
	// blockedV4Prefixes are the v4 ranges that must never be dialed even though
	// netip.IsPrivate/IsLoopback/IsLinkLocal cover most of them. CGNAT and the
	// IETF-reserved/documentation ranges are not flagged private by IsPrivate.
	blockedV4Prefixes = []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
		netip.MustParsePrefix("169.254.0.0/16"),  // link-local / metadata
		netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
		netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
		netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast
		netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
		netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
		netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
		netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	}
	blockedV6Prefixes = []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/32"), // documentation
		netip.MustParsePrefix("2001::/32"),     // Teredo
		netip.MustParsePrefix("2002::/16"),     // 6to4
	}
)

// errBlockedAddress is returned when a hostname resolves to any disallowed
// address (fail-closed SSRF gate).
var errBlockedAddress = errors.New("hook: resolved address is not a global routable address")

// validateAddresses rejects the whole set if any address is blocked.
func validateAddresses(addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return errBlockedAddress
	}
	for _, a := range addrs {
		if !a.IsValid() || addressBlocked(a) {
			return errBlockedAddress
		}
	}
	return nil
}

// addressBlocked reports whether a single address is never acceptable to dial.
func addressBlocked(a netip.Addr) bool {
	if !a.IsValid() {
		return true
	}
	// IPv4-mapped IPv6 (e.g. ::ffff:192.0.2.1) must be treated as IPv4 and can
	// carry a non-global mapped address; reject outright.
	if a.Is4In6() {
		return true
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	if a.Is4() {
		for _, p := range blockedV4Prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	for _, p := range blockedV6Prefixes {
		if p.Contains(a) {
			return true
		}
	}
	// Any non-global-scope IPv6 (site-local fec0::/10 legacy, interface-local
	// ff01/ff02) is already covered by IsLinkLocal/IsMulticast/IsPrivate.
	return false
}

// canonicalIPLiteral returns the parsed address when host is an unambiguous
// canonical IP literal (dotted-quad or full IPv6), else ok=false.
func canonicalIPLiteral(host string) (netip.Addr, bool) {
	if host == "" {
		return netip.Addr{}, false
	}
	if strings.ContainsAny(host, "%") {
		return netip.Addr{}, false // zone identifiers are rejected
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a, true
}

// ambiguousIPLiteral rejects non-canonical host spellings that resolvers or
// legacy parsers may interpret as IP addresses ("mixed-encoding IP literals"):
// all-numeric single tokens, dotted all-numeric shorthands, leading-zero octal
// octets and 0x hex forms. A legitimate hostname contains letters.
func ambiguousIPLiteral(host string) bool {
	if _, ok := canonicalIPLiteral(host); ok {
		return false // a canonical literal is handled by the caller, not ambiguous
	}
	lower := strings.ToLower(host)
	if strings.Contains(lower, "0x") || strings.Contains(lower, "%") {
		return true
	}
	segs := strings.Split(host, ".")
	allNumeric := true
	for _, s := range segs {
		if s == "" {
			allNumeric = false
			continue
		}
		if !isDigitString(s) {
			allNumeric = false
		} else if len(s) > 1 && s[0] == '0' {
			return true // leading-zero octal form
		}
	}
	return allNumeric // "127.1", "2130706433", "1.2.3"
}

func isDigitString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// hostnameIssues validates the hostname text form: CRLF, empty labels, label
// overlongs, trailing-dot ambiguity, forbidden characters and zone ids.
func hostnameIssues(host string) error {
	if host == "" {
		return errors.New("hook: empty host")
	}
	if strings.ContainsAny(host, "\r\n\t ") {
		return errors.New("hook: host contains whitespace/CRLF")
	}
	if strings.HasSuffix(host, ".") {
		return errors.New("hook: trailing-dot host is ambiguous")
	}
	if strings.Contains(host, "%") {
		return errors.New("hook: zone identifier in host is rejected")
	}
	if len(host) > 253 {
		return errors.New("hook: host name is too long")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return errors.New("hook: empty host label")
		}
		if len(label) > 63 {
			return errors.New("hook: host label is too long")
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			default:
				if r > 127 {
					return errors.New("hook: non-ASCII host (IDNA) is rejected")
				}
				return errors.New("hook: host contains an invalid character")
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("hook: host label starts or ends with a hyphen")
		}
	}
	return nil
}
