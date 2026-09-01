// P14 Story 4 (agent side): accepting a controller key-rotation pin only after
// verifying the signed certificate against the current pin and persisting the
// higher generation. Downgrade / wrong signer / foreign instance fail closed.
//
// RED: when first written, `AcceptControllerRotationPin` did not exist (no real
// certificate decode -> the tests could not compile), the generation-vs-pin
// anti-downgrade comparison was unimplemented, and same-generation / wrong-
// instance / forged certificates were not refused. See internal/security/tdd-red.
package reconcile

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/security"
)

func seedPin(t *testing.T, st *localstate.Store, instanceID string, pub ed25519.PublicKey) {
	t.Helper()
	if err := st.SaveControllerPin(localstate.ControllerPin{
		InstanceID: instanceID, KeyID: "pin-key-1",
		PublicKeyRaw: append(ed25519.PublicKey(nil), pub...), Generation: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestAgentAcceptsRotationPinEndToEnd signs a real rotation cert with the old
// key, feeds it through the agent acceptance path, and the successor pin is
// durable with the higher generation.
func TestAgentAcceptsRotationPinEndToEnd(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	_, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPub := newPriv.Public().(ed25519.PublicKey)
	seedPin(t, st, "inst-1", oldPub)

	now := time.Now().Unix()
	cert := security.NewRotationCertificate(
		"controller", oldPub, 1, "pin-key-1", newPub, 2, security.KeyIDOf(newPub), now, now+3600)
	if err := security.SignRotationCertificate(&cert, oldPriv); err != nil {
		t.Fatal(err)
	}
	raw, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	next, decoded, err := AcceptControllerRotationPin(st, "inst-1", []byte(raw))
	if err != nil {
		t.Fatalf("accept rotation pin: %v", err)
	}
	if next.Generation != 2 || next.KeyID == "" {
		t.Fatalf("next pin = %+v", next)
	}
	if decoded.NewKeyID != next.KeyID {
		t.Fatalf("decoded new id %q != persisted %q", decoded.NewKeyID, next.KeyID)
	}
	persisted, found, err := st.ControllerPin("inst-1")
	if err != nil || !found {
		t.Fatalf("persisted pin missing found=%v err=%v", found, err)
	}
	if persisted.Generation != 2 {
		t.Fatalf("persisted generation = %d, want 2", persisted.Generation)
	}
}

// TestAgentRefusesDowngradePin: a legitimate sequence then a downgrade cert is
// refused (anti-downgrade persists the highest generation).
func TestAgentRefusesDowngradePin(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	_, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub := newPriv.Public().(ed25519.PublicKey)
	seedPin(t, st, "inst-1", oldPub)

	now := time.Now().Unix()
	cert := security.NewRotationCertificate("controller", oldPub, 1, "pin-key-1", newPub, 1, security.KeyIDOf(newPub), now, now+3600)
	_ = security.SignRotationCertificate(&cert, oldPriv)
	raw, _ := cert.Encode()
	if _, _, err := AcceptControllerRotationPin(st, "inst-1", []byte(raw)); err == nil {
		t.Fatal("same-generation rotation accepted")
	}
	persisted, _, _ := st.ControllerPin("inst-1")
	if persisted.Generation != 1 {
		t.Fatalf("downgrade changed persisted generation to %d", persisted.Generation)
	}
}

// TestAgentRefusesWrongInstance: a certificate bound to a different pinned
// controller instance fails closed.
func TestAgentRefusesWrongInstance(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	_, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub := newPriv.Public().(ed25519.PublicKey)
	seedPin(t, st, "inst-A", oldPub)

	now := time.Now().Unix()
	cert := security.NewRotationCertificate("controller", oldPub, 1, "pin-key-1", newPub, 2, security.KeyIDOf(newPub), now, now+3600)
	_ = security.SignRotationCertificate(&cert, oldPriv)
	raw, _ := cert.Encode()
	if _, _, err := AcceptControllerRotationPin(st, "inst-B", []byte(raw)); err == nil {
		t.Fatal("rotation for a different controller instance accepted")
	}
}
