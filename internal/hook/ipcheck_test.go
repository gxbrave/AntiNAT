package hook

import (
	"net/netip"
	"strings"
	"testing"
)

// RED P16 Story 2 (a): private/rfc1918, loopback, link-local, multicast,
// CGNAT, ULA, IPv4-mapped IPv6 and the metadata address are all blocked.
func TestAddressBlockedUnits(t *testing.T) {
	blocked := []string{
		"10.0.0.1", "192.168.1.1", "172.16.0.1", // RFC1918 private
		"127.0.0.1", "::1", // loopback
		"169.254.169.254", "169.254.0.1", "fe80::1", // link-local + metadata
		"224.0.0.1", "ff02::1", // multicast
		"100.64.0.1", "100.127.255.254", // CGNAT
		"fc00::1", "fd12:3456::1", // IPv6 ULA
		"::ffff:192.0.2.1", // IPv4-mapped IPv6
		"0.0.0.0", "::",    // unspecified
		"192.0.2.1", "198.51.100.1", "203.0.113.1", "240.0.0.1", "2001:db8::1", "2002::1",
	}
	for _, s := range blocked {
		if !addressBlocked(mustAddr(t, s)) {
			t.Errorf("%s must be blocked", s)
		}
	}
	allowed := []string{"8.8.8.8", "93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if addressBlocked(mustAddr(t, s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return a
}

// RED P16 Story 2 (b): validateAddresses rejects the whole set when ANY record
// is blocked — a mixed public/private answer must not be dialed.
func TestValidateAddressesRejectsMixedPublicPrivate(t *testing.T) {
	mixed := []netip.Addr{mustAddr(t, "8.8.8.8"), mustAddr(t, "10.0.0.1")}
	if err := validateAddresses(mixed); err == nil {
		t.Fatal("mixed public/private A/AAAA accepted; want rejection")
	}
	allPublic := []netip.Addr{mustAddr(t, "8.8.8.8"), mustAddr(t, "2606:4700:4700::1111")}
	if err := validateAddresses(allPublic); err != nil {
		t.Fatalf("all-public addresses rejected: %v", err)
	}
	if err := validateAddresses(nil); err == nil {
		t.Fatal("empty address set accepted")
	}
}

// RED P16 Story 2 (c): ambiguous IP-literal spellings (single-number,
// hex, octal, numeric shorthand) are rejected as dangerous ambiguity.
func TestAmbiguousIPLiteralRejectsMixedEncodings(t *testing.T) {
	for _, s := range []string{"2130706433", "0x7f000001", "127.1", "0177.0.0.1", "0300.0250.0001.0001", "1.2.3"} {
		if !ambiguousIPLiteral(s) {
			t.Errorf("%s must be treated as an ambiguous ip literal", s)
		}
	}
	for _, s := range []string{"example.com", "hooks.example.com", "example-1.test"} {
		if ambiguousIPLiteral(s) {
			t.Errorf("%s must NOT be treated as an ip literal", s)
		}
	}
	// Canonical IPs are handled by canonicalIPLiteral, not this helper.
	if ambiguousIPLiteral("127.0.0.1") {
		t.Error("canonical dotted-quad must parse first, not be rejected as ambiguous")
	}
}

// RED P16 Story 2 (d): hostname form guards — trailing dots, zone ids,
// CRLF, overlong labels, non-ASCII IDNA, empty labels and hyphen edges.
func TestHostnameIssuesRejectDangerousForms(t *testing.T) {
	for _, s := range []string{
		"example.com.", "fe80::1%25eth0", "a\r\nb.example.com",
		"a\nb.example.com", "example..com", ".example.com", strings.Repeat("a", 64) + ".com",
		"exämple.com", "-bad.example.com", "bad-.example.com", "example.com/evil",
	} {
		if err := hostnameIssues(s); err == nil {
			t.Errorf("%q must be rejected", s)
		}
	}
	for _, s := range []string{"example.com", "hooks.example.com", "example-1.test.local"} {
		if err := hostnameIssues(s); err != nil {
			t.Errorf("%q must be accepted: %v", s, err)
		}
	}
}

// RED P16 Story 2 (e): canonical IP literal detection accepts dotted-quad and
// full IPv6 but refuses zone ids and shorthand.
func TestCanonicalIPLiteral(t *testing.T) {
	if _, ok := canonicalIPLiteral("93.184.216.34"); !ok {
		t.Fatal("dotted-quad not recognized as canonical")
	}
	if _, ok := canonicalIPLiteral("2606:4700::1111"); !ok {
		t.Fatal("full IPv6 not recognized as canonical")
	}
	for _, s := range []string{"127.1", "fe80::1%eth0", "0x7f000001"} {
		if _, ok := canonicalIPLiteral(s); ok {
			t.Errorf("%q must not parse as canonical", s)
		}
	}
}
