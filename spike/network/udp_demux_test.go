package network

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestUDPDemuxConsumesSTUNOnlyForFullOutstandingMatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	server := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 3478}
	transaction := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	valid := EncodeSTUNFixture(STUNSuccessResponse, transaction)

	tests := []struct {
		name     string
		source   *net.UDPAddr
		payload  []byte
		deadline time.Time
		want     DatagramKind
	}{
		{name: "exact", source: server, payload: valid, deadline: now.Add(time.Second), want: DatagramSTUN},
		{name: "wrong source", source: &net.UDPAddr{IP: server.IP, Port: 9999}, payload: valid, deadline: now.Add(time.Second), want: DatagramDropped},
		{name: "wrong transaction", source: server, payload: EncodeSTUNFixture(STUNSuccessResponse, [12]byte{99}), deadline: now.Add(time.Second), want: DatagramDropped},
		{name: "wrong class", source: server, payload: EncodeSTUNFixture(STUNRequest, transaction), deadline: now.Add(time.Second), want: DatagramDropped},
		{name: "expired", source: server, payload: valid, deadline: now.Add(-time.Nanosecond), want: DatagramDropped},
		{name: "lookalike", source: server, payload: append([]byte("STUN"), make([]byte, 13)...), deadline: now.Add(time.Second), want: DatagramData},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			demux := NewUDPDemux(8)
			demux.ExpectSTUN(server, STUNSuccessResponse, transaction, test.deadline)
			if got := demux.Classify(test.source, test.payload, now); got != test.want {
				t.Fatalf("classify = %s, want %s", got, test.want)
			}
		})
	}
}

func TestUDPDemuxConsumesProbeOnlyForAuthenticatedOutstandingMatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	provider := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 41000}
	key := []byte("provider-key-for-p02-spike")
	expected := UDPProbeFields{
		ProbeID:    [16]byte{1},
		Activation: [16]byte{2},
		Endpoint:   &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 3111},
		Challenge:  [32]byte{3},
	}
	valid := EncodeUDPProbeFixture(expected, key)

	tests := []struct {
		name     string
		source   *net.UDPAddr
		payload  []byte
		expected UDPProbeFields
		key      []byte
		deadline time.Time
		want     DatagramKind
	}{
		{name: "exact", source: provider, payload: valid, expected: expected, key: key, deadline: now.Add(time.Second), want: DatagramProbe},
		{name: "wrong source", source: &net.UDPAddr{IP: provider.IP, Port: provider.Port + 1}, payload: valid, expected: expected, key: key, deadline: now.Add(time.Second), want: DatagramDropped},
		{name: "wrong probe", source: provider, payload: valid, expected: withProbeID(expected, [16]byte{9}), key: key, deadline: now.Add(time.Second), want: DatagramDropped},
		{name: "wrong activation", source: provider, payload: valid, expected: withActivation(expected, [16]byte{9}), key: key, deadline: now.Add(time.Second), want: DatagramDropped},
		{name: "wrong endpoint", source: provider, payload: valid, expected: withEndpoint(expected, &net.UDPAddr{IP: expected.Endpoint.IP, Port: 9999}), key: key, deadline: now.Add(time.Second), want: DatagramDropped},
		{name: "wrong challenge", source: provider, payload: valid, expected: withChallenge(expected, [32]byte{9}), key: key, deadline: now.Add(time.Second), want: DatagramDropped},
		{name: "bad signature", source: provider, payload: valid, expected: expected, key: []byte("different-key"), deadline: now.Add(time.Second), want: DatagramDropped},
		{name: "expired", source: provider, payload: valid, expected: expected, key: key, deadline: now.Add(-time.Nanosecond), want: DatagramDropped},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			demux := NewUDPDemux(16)
			demux.ExpectProbe(provider, test.expected, test.key, test.deadline)
			if got := demux.Classify(test.source, test.payload, now); got != test.want {
				t.Fatalf("classify = %s, want %s", got, test.want)
			}
		})
	}
}

func withProbeID(fields UDPProbeFields, probeID [16]byte) UDPProbeFields {
	fields.ProbeID = probeID
	return fields
}

func withActivation(fields UDPProbeFields, activation [16]byte) UDPProbeFields {
	fields.Activation = activation
	return fields
}

func withEndpoint(fields UDPProbeFields, endpoint *net.UDPAddr) UDPProbeFields {
	fields.Endpoint = endpoint
	return fields
}

func withChallenge(fields UDPProbeFields, challenge [32]byte) UDPProbeFields {
	fields.Challenge = challenge
	return fields
}

func TestUDPDemuxRejectsProbeReplayAfterOutstandingMatchIsConsumed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	provider := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 41000}
	key := []byte("provider-key-for-p02-spike")
	fields := UDPProbeFields{
		ProbeID:    [16]byte{1},
		Activation: [16]byte{2},
		Endpoint:   &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 3111},
		Challenge:  [32]byte{3},
	}
	demux := NewUDPDemux(8)
	demux.ExpectProbe(provider, fields, key, now.Add(time.Second))
	payload := EncodeUDPProbeFixture(fields, key)
	if got := demux.Classify(provider, payload, now); got != DatagramProbe {
		t.Fatalf("first classify = %s, want PROBE", got)
	}
	if got := demux.Classify(provider, payload, now); got != DatagramDropped {
		t.Fatalf("replay classify = %s, want DROPPED", got)
	}
}

func TestUDPDemuxBoundsNewDataSessions(t *testing.T) {
	demux := NewUDPDemux(2)
	now := time.Unix(1_700_000_000, 0)
	first := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1001}
	second := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1002}
	third := &net.UDPAddr{IP: net.ParseIP("192.0.2.3"), Port: 1003}
	if got := demux.Classify(first, []byte("one"), now); got != DatagramData {
		t.Fatalf("first session = %s, want DATA", got)
	}
	if got := demux.Classify(second, []byte("two"), now); got != DatagramData {
		t.Fatalf("second session = %s, want DATA", got)
	}
	if got := demux.Classify(third, []byte("three"), now); got != DatagramDropped {
		t.Fatalf("third session = %s, want DROPPED", got)
	}
	if got := demux.Classify(first, []byte("again"), now); got != DatagramData {
		t.Fatalf("existing session = %s, want DATA", got)
	}
}

func TestUDPDemuxDoesNotRouteMalformedReservedFramesAsData(t *testing.T) {
	demux := NewUDPDemux(8)
	source := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1001}
	for _, payload := range [][]byte{[]byte("STN1"), []byte("PRB1"), []byte("WAN1"), []byte("ACK1"), []byte("ARM1")} {
		if got := demux.Classify(source, payload, time.Unix(1_700_000_000, 0)); got != DatagramDropped {
			t.Fatalf("reserved payload %q classified as %s, want DROPPED", payload, got)
		}
	}
}

func TestUDPDemuxEvictsExpiredStateAndBoundsPerSourceSessions(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	demux := NewUDPDemuxWithLimits(2, 1, 1, 1, time.Second)
	first := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1001}
	secondPort := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1002}
	other := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1003}
	if got := demux.Classify(first, []byte("one"), now); got != DatagramData {
		t.Fatalf("first session = %s, want DATA", got)
	}
	if got := demux.Classify(secondPort, []byte("two"), now); got != DatagramDropped {
		t.Fatalf("same-source churn = %s, want DROPPED", got)
	}
	if got := demux.Classify(other, []byte("three"), now); got != DatagramData {
		t.Fatalf("second source = %s, want DATA", got)
	}
	if got := demux.Classify(first, []byte("expired"), now.Add(2*time.Second)); got != DatagramData {
		t.Fatalf("expired first session = %s, want DATA after eviction", got)
	}
	if got := demux.SessionCount(); got != 1 {
		t.Fatalf("session count after expiry = %d, want 1", got)
	}
}

func TestUDPDemuxExpectationStateIsBoundedAndExpires(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	demux := NewUDPDemuxWithLimits(8, 8, 1, 1, time.Second)
	server := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 3478}
	if err := demux.ExpectSTUN(server, STUNSuccessResponse, [12]byte{1}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := demux.ExpectSTUN(server, STUNSuccessResponse, [12]byte{2}, now.Add(time.Second)); !errors.Is(err, ErrDemuxStateFull) {
		t.Fatalf("second STUN expectation error = %v, want ErrDemuxStateFull", err)
	}
	demux.Expire(now.Add(2 * time.Second))
	if err := demux.ExpectSTUN(server, STUNSuccessResponse, [12]byte{2}, now.Add(3*time.Second)); err != nil {
		t.Fatalf("STUN expectation after expiry: %v", err)
	}
}

func TestUDPProbeFixtureRejectsMalformedEndpointInsteadOfPanicking(t *testing.T) {
	invalid := UDPProbeFields{Endpoint: nil}
	if payload := EncodeUDPProbeFixture(invalid, []byte("key")); payload != nil {
		t.Fatal("nil endpoint unexpectedly encoded")
	}
	invalid.Endpoint = &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 0}
	if payload := EncodeUDPProbeFixture(invalid, []byte("key")); payload != nil {
		t.Fatal("zero port unexpectedly encoded")
	}
	invalid.Endpoint = &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 3111}
	if payload := EncodeUDPProbeFixture(invalid, nil); payload != nil {
		t.Fatal("empty key unexpectedly encoded")
	}
}
