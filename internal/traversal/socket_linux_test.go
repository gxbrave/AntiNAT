// Story 1 RED: /proc/net/route parsing and real-host determinism.
package traversal

import (
	"testing"
)

func TestParseProcNetRouteDefault(t *testing.T) {
	fixture := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0102A8C0	0003	0	0	0	00000000	0	0	0
`
	gateway, iface, ok, err := parseProcNetRoute([]byte(fixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !ok {
		t.Fatal("default route not detected")
	}
	if iface != "eth0" {
		t.Fatalf("iface = %q, want eth0", iface)
	}
	// 0102A8C0 is little-endian: c0 a8 02 01 = 192.168.2.1
	if gateway != addr("192.168.2.1") {
		t.Fatalf("gateway = %v, want 192.168.2.1", gateway)
	}
}

func TestParseProcNetRouteNoDefault(t *testing.T) {
	fixture := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00011AA8	00000000	0001	0	0	0	00FFFFFF	0	0	0
`
	_, _, ok, err := parseProcNetRoute([]byte(fixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ok {
		t.Fatal("non-default route must not count as a default route")
	}
}

func TestParseProcNetRoutePicksLowestMetric(t *testing.T) {
	fixture := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth1	00000000	0102A8C0	0003	0	0	100	00000000	0	0	0
eth0	00000000	FE01A8C0	0003	0	0	50	00000000	0	0	0
`
	gateway, iface, ok, err := parseProcNetRoute([]byte(fixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !ok {
		t.Fatal("default route not detected")
	}
	if iface != "eth0" {
		t.Fatalf("iface = %q, want lowest-metric eth0", iface)
	}
	// FE01A8C0 little-endian: c0 a8 01 fe = 192.168.1.254
	if gateway != addr("192.168.1.254") {
		t.Fatalf("gateway = %v, want 192.168.1.254", gateway)
	}
}

func TestParseProcNetRouteTieBreaksByInterfaceName(t *testing.T) {
	fixture := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth1	00000000	0102A8C0	0003	0	0	50	00000000	0	0	0
eth0	00000000	FE01A8C0	0003	0	0	50	00000000	0	0	0
`
	_, iface, ok, err := parseProcNetRoute([]byte(fixture))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !ok {
		t.Fatal("default route not detected")
	}
	if iface != "eth0" {
		t.Fatalf("tie must break lexicographically, iface = %q, want eth0", iface)
	}
}

func TestParseProcNetRouteRejectsGarbage(t *testing.T) {
	for _, fixture := range []string{
		"not a route table",
		"Iface	Destination	Gateway 	Flags\neth0	ZZZZ0000	00000000	0003\n",
	} {
		if _, _, _, err := parseProcNetRoute([]byte(fixture)); err == nil {
			t.Fatalf("garbage %q must error", fixture)
		}
	}
}

func TestParseProcNetRouteHeaderOnlyIsEmptyTable(t *testing.T) {
	_, _, ok, err := parseProcNetRoute([]byte("Iface	Destination	Gateway\n"))
	if err != nil {
		t.Fatalf("header-only table must parse: %v", err)
	}
	if ok {
		t.Fatal("header-only table must not contain a default route")
	}
}

func TestHostRouteTableDeterministic(t *testing.T) {
	table := HostRouteTable{}
	first, capability, err := Assess(table)
	if err != nil {
		t.Logf("host has no assessable direct-v4 source (capability %q): %v", capability, err)
		t.Skip("host environment lacks an IPv4 route table to assess")
	}
	for round := 0; round < 3; round++ {
		got, gotCapability, err := Assess(table)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if got != first || gotCapability != capability {
			t.Fatalf("round %d: unstable host assessment %+v/%q vs %+v/%q", round, got, gotCapability, first, capability)
		}
	}
	fp1, err := Fingerprint(table)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := Fingerprint(table)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Fatalf("host fingerprint unstable: %q vs %q", fp1, fp2)
	}
}
