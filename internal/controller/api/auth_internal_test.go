package api

// RED M3: the per-peer login attempt map was unbounded; a flood of distinct
// source peers could grow entries without limit. The fix caps the map at
// maxLoginLimiterPeers and evicts expired windows before refusing a brand-new
// peer. This test fails on the pre-fix code because peerCount grows past the
// cap.

import (
	"strconv"
	"testing"
	"time"
)

func TestP15Repair1M3LoginLimiterPeerMapBounded(t *testing.T) {
	l := newLoginLimiter()
	l.limit = 2
	l.window = time.Minute
	// Saturate the map with distinct peers.
	for i := 0; i < int(l.maxEntries)+100; i++ {
		l.allow(peerKey(i))
		if n := l.peerCount(); n > l.maxEntries {
			t.Fatalf("peer map grew to %d beyond cap %d", n, l.maxEntries)
		}
	}
	if n := l.peerCount(); n > l.maxEntries {
		t.Fatalf("peer map = %d, want <= %d", n, l.maxEntries)
	}
	// A peer already in the map still gets rate-limited normally.
	if !l.allow(peerKey(0)) {
		t.Fatal("known in-window peer should still be allowed (count < limit)")
	}
}

func TestP15Repair1M3LoginLimiterEvictsExpiredPeers(t *testing.T) {
	base := time.Now()
	l := newLoginLimiter()
	l.now = func() time.Time { return base }
	l.limit = 10
	l.window = time.Minute
	for i := 0; i < l.maxEntries; i++ {
		l.allow(peerKey(i))
	}
	if n := l.peerCount(); n != l.maxEntries {
		t.Fatalf("seed peerCount = %d, want %d", n, l.maxEntries)
	}
	// Advance the clock past every window and insert one new peer; expired
	// entries must be evicted so the new peer is admitted.
	base = base.Add(2 * time.Minute)
	if !l.allow("brand-new-peer") {
		t.Fatal("brand-new peer refused after expiry sweep")
	}
	if n := l.peerCount(); n > l.maxEntries {
		t.Fatalf("peer count after expiry sweep = %d, want <= %d", n, l.maxEntries)
	}
}

func peerKey(i int) string {
	return "10.0.0." + strconv.Itoa(1+i%254) + ":" + strconv.Itoa(i%65536)
}
