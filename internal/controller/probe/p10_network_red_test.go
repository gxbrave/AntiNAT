package probe

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

func TestProviderReplayCanonicalizesProbeID(t *testing.T) {
	ctrlPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, providerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProvider(ProviderConfig{ControllerPublicKey: ctrlPub, ProviderPrivateKey: providerPriv})
	if err != nil {
		t.Fatal(err)
	}
	lower := &providerRequest{
		Schema: providerRequestSchema, ControllerInstance: "i", ControllerKeyID: "k",
		NodePublicKey: strings.Repeat("11", 32), NodePublicKeyHash: strings.Repeat("22", 32),
		ProbeID: strings.Repeat("ab", 16), ProviderID: strings.Repeat("cd", 16), Activation: strings.Repeat("ef", 16),
		Endpoint: "198.51.100.7:80", ExpectedSourceIP: "c6336409", ExpiryOpaque: strings.Repeat("12", 16),
		TTLMS: 30000, ArmDigest: strings.Repeat("34", 32), TimestampUnix: 100,
	}
	upper := *lower
	upper.ProbeID = strings.ToUpper(lower.ProbeID)
	if got := p.admitReplay(lower, time.Unix(100, 0)); got != "" {
		t.Fatalf("first admission = %q", got)
	}
	if got := p.admitReplay(&upper, time.Unix(100, 0)); got != "replay" {
		t.Fatalf("case-variant admission = %q, want replay", got)
	}
}

func TestProviderACKMustBindToWAN1(t *testing.T) {
	var frame protocol.ProviderFrame
	frame.ArmDigest[0] = 1
	frame.Challenge[0] = 2
	ack := protocol.ProbeACK{ArmDigest: frame.ArmDigest, ChallengeHash: frame.ChallengeHash()}
	if !verifyProbeACKBinding(frame, ack) {
		t.Fatal("matching ACK binding rejected")
	}
	ack.ArmDigest[0] = 9
	if verifyProbeACKBinding(frame, ack) {
		t.Fatal("ACK with mismatched arm digest accepted")
	}
}
