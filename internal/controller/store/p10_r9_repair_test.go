package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

func TestApplyForwardDesiredPublishesCurrentActivationForRevision(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateNode(Node{ID: "node-activation", Name: "node"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{ID: "fwd-activation", NodeID: "node-activation", Name: "forward", Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyForwardDesired(ForwardSpec{
		ID: "spec-activation", ForwardID: "fwd-activation", Revision: 1,
		SpecJSON: `{"forward_id":"fwd-activation","desired_revision":1}`,
	}, ControlOutboxItem{OperationID: "op-activation", MessageType: "desired", NodeID: "node-activation", SemanticPayload: "{}"}); err != nil {
		t.Fatal(err)
	}
	fwd, err := s.GetForward("fwd-activation")
	if err != nil {
		t.Fatal(err)
	}
	activation := protocol.ActivationID("fwd-activation", 1)
	if got, want := fwd.CurrentActivationID, hex.EncodeToString(activation[:]); got != want {
		t.Fatalf("current activation = %q, want %q", got, want)
	}
}

func TestOpenRejectsFutureSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO schema_migrations(version, name, applied_at) VALUES(999, 'future', 1)`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("Open future schema error = %v, want ErrSchemaTooNew", err)
	}
}

func TestApplyForwardDeleteRejectsMismatchedOutboxIdentity(t *testing.T) {
	s := openTestStore(t)
	mustCreateNode(t, s, "node-delete")
	mustCreateForward(t, s, Forward{ID: "forward-delete", NodeID: "node-delete", Name: "forward", Protocol: "tcp"})
	err := s.ApplyForwardDelete(ForwardDeletionOperation{ID: "delete-op", ForwardID: "forward-delete", DesiredRevision: 0}, ControlOutboxItem{OperationID: "outbox-op", MessageType: "delete", NodeID: "node-delete", SemanticPayload: "{}"})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("mismatched outbox identity error = %v, want ErrIdempotencyConflict", err)
	}
}

func TestApplyForwardDeleteRejectsNextRevisionRepresentation(t *testing.T) {
	s := openTestStore(t)
	mustCreateNode(t, s, "node-delete-next")
	mustCreateForward(t, s, Forward{ID: "forward-delete-next", NodeID: "node-delete-next", Name: "forward", Protocol: "tcp"})
	err := s.ApplyForwardDelete(ForwardDeletionOperation{ID: "delete-next", ForwardID: "forward-delete-next", DesiredRevision: 1}, ControlOutboxItem{OperationID: "delete-next", MessageType: "delete", NodeID: "node-delete-next", SemanticPayload: "{}"})
	if !errors.Is(err, ErrCASConflict) {
		t.Fatalf("next-revision delete error = %v, want ErrCASConflict", err)
	}
}
func TestProbeOperationDigestLookupScansBeyondOnePage(t *testing.T) {
	s := openTestStore(t)
	mustCreateNode(t, s, "node-1")
	mustCreateForward(t, s, Forward{ID: "forward-1", NodeID: "node-1", Name: "forward-1", Protocol: "tcp"})
	if _, err := s.CreateProbeProvider(ProbeProvider{ID: "provider-1", Name: "provider-1", PublicKey: "key", EgressIP: "198.51.100.9", Endpoint: "https://provider.invalid", Enabled: true, IndependentVantage: true}); err != nil {
		t.Fatal(err)
	}
	var target protocol.ProbeArm
	for i := 0; i < 513; i++ {
		var arm protocol.ProbeArm
		if _, err := rand.Read(arm.ProbeID[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(arm.ProviderID[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(arm.ProviderPublicKey[:]); err != nil {
			t.Fatal(err)
		}
		copy(arm.Activation[:], "activation")
		arm.Endpoint = "198.51.100.7:8080"
		arm.TTLMS = 30_000
		if _, err := rand.Read(arm.ExpiryOpaque[:]); err != nil {
			t.Fatal(err)
		}
		if i == 512 {
			target = arm
		}
		if _, err := s.CreateProbeOperation(ProbeOperation{
			ID:           "probe-" + hex.EncodeToString(arm.ProbeID[:]),
			NodeID:       "node-1",
			ForwardID:    "forward-1",
			ActivationID: "activation-1",
			ProviderID:   "provider-1",
			Status:       "PENDING",
			ArmHex:       hex.EncodeToString(arm.Canonical()),
			Endpoint:     arm.Endpoint,
			TTLMS:        arm.TTLMS,
			ExpiresAt:    time.Now().Add(time.Duration(i+1) * time.Minute).Unix(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ProbeOperationByArmDigest(target.Digest())
	if err != nil {
		t.Fatalf("lookup newest operation: %v", err)
	}
	if got.ID != "probe-"+hex.EncodeToString(target.ProbeID[:]) {
		t.Fatalf("lookup returned %q, want target operation", got.ID)
	}
}
