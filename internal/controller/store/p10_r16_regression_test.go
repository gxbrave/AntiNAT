package store

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

func TestR16ProbeArmRejectsAdvancedForwardRevision(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 80_000)
	if err := s.CreateNode(Node{ID: "r16-cas-node", Name: "r16-cas-node"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{
		ID: "r16-cas-forward", NodeID: "r16-cas-node", Name: "r16-cas-forward",
		Protocol: "tcp", CurrentActivationID: "r16-activation", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyForwardDelete(ForwardDeletionOperation{
		ID: "r16-delete", ForwardID: "r16-cas-forward", Status: "PENDING", DesiredRevision: 1,
	}, ControlOutboxItem{
		OperationID: "r16-delete", MessageType: "desired", NodeID: "r16-cas-node", SemanticPayload: `{}`,
	}); err != nil {
		t.Fatal(err)
	}

	_, err := s.CreateProbeOperationBundle(ProbeOperation{
		ID: "r16-stale-arm", NodeID: "r16-cas-node", ForwardID: "r16-cas-forward",
		ActivationID: "r16-activation", ExpectedForwardRevision: 1, ProviderID: "r16-provider",
		Status: "PENDING", Endpoint: "198.51.100.7:8080", ArmHex: "41524d31",
		TTLMS: 30_000, ExpiryOpaque: "00112233445566778899aabbccddeeff", ExpiresAt: time.Unix(80_030, 0).Unix(),
	}, ControlOutboxItem{
		OperationID: "r16-stale-arm", MessageType: "probe_arm", NodeID: "r16-cas-node", SemanticPayload: "arm",
	})
	if !errors.Is(err, ErrCASConflict) {
		t.Fatalf("stale arm error = %v, want ErrCASConflict", err)
	}
	if _, err := s.GetProbeOperation("r16-stale-arm"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale arm operation persisted: %v", err)
	}
}

func TestR16ProbeJoinRejectsDeletionRevisionAdvance(t *testing.T) {
	fixture := newAuthenticatedJoinFixture(t)
	if err := fixture.store.SetForwardRuntimeStatus(
		fixture.forwardID,
		fixture.activationID,
		legalRuntimeSnapshot("NOT_TESTED", "NOT_TESTED", "NONE"),
	); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.ApplyForwardDelete(ForwardDeletionOperation{
		ID: "r16-delete-during-join", ForwardID: fixture.forwardID, Status: "PENDING", DesiredRevision: 1,
	}, ControlOutboxItem{
		OperationID: "r16-delete-during-join", MessageType: "desired", NodeID: "join-node", SemanticPayload: `{}`,
	}); err != nil {
		t.Fatal(err)
	}
	nodePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	err := fixture.store.PublishProbeJoin(
		fixture.operationID,
		"IN_FLIGHT",
		fixture.forwardID,
		fixture.activationID,
		authenticatedJoinSnapshot,
		nodePrivate.Public().(ed25519.PublicKey),
	)
	if !errors.Is(err, ErrCASConflict) {
		t.Fatalf("stale join error = %v, want ErrCASConflict", err)
	}
	op, err := fixture.store.GetProbeOperation(fixture.operationID)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != "IN_FLIGHT" {
		t.Fatalf("stale join changed operation status to %q", op.Status)
	}
}

func TestR16ProbeOutcomeRejectsDeletionRevisionAdvance(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 81_000)
	if err := s.CreateNode(Node{ID: "r16-outcome-node", Name: "r16-outcome-node"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{
		ID: "r16-outcome-forward", NodeID: "r16-outcome-node", Name: "r16-outcome-forward",
		Protocol: "tcp", CurrentActivationID: "r16-outcome-activation", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProbeOperation(ProbeOperation{
		ID: "r16-outcome-probe", NodeID: "r16-outcome-node", ForwardID: "r16-outcome-forward",
		ActivationID: "r16-outcome-activation", ProviderID: "r16-provider",
		Status: string(protocol.OutcomeRejected), Endpoint: "198.51.100.7:8080", ExpiresAt: 81_030,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyForwardDelete(ForwardDeletionOperation{
		ID: "r16-outcome-delete", ForwardID: "r16-outcome-forward", Status: "PENDING", DesiredRevision: 1,
	}, ControlOutboxItem{
		OperationID: "r16-outcome-delete", MessageType: "desired", NodeID: "r16-outcome-node", SemanticPayload: `{}`,
	}); err != nil {
		t.Fatal(err)
	}
	disposition, err := s.QueueProbeOutcome("r16-outcome-probe", protocol.OutcomeRejected)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != "STALE" {
		t.Fatalf("post-delete outcome disposition = %q, want STALE", disposition)
	}
	if _, err := s.ControlOutboxItemByOperation("r16-outcome-probe", "probe_outcome"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("post-delete outcome was enqueued: %v", err)
	}
}

func TestR16TerminalDeliveryExpiryPreservesSentWork(t *testing.T) {
	for _, state := range []string{"SENT", "SEMANTIC_ACKED"} {
		t.Run(state, func(t *testing.T) {
			s := openTestStore(t)
			withStoreNow(t, 82_000)
			if err := s.CreateNode(Node{ID: "node-delivery-r13", Name: "r16-delivery-node"}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.CreateForward(Forward{
				ID: "r16-delivery-forward", NodeID: "node-delivery-r13", Name: "r16-delivery-forward",
				Protocol: "tcp", CurrentActivationID: "r16-delivery-activation", Revision: 1,
			}); err != nil {
				t.Fatal(err)
			}
			createR13TerminalProbe(t, s, "r16-delivery-probe", "r16-delivery-forward", "r16-delivery-activation", 1)
			if got, err := s.QueueProbeOutcome("r16-delivery-probe", protocol.OutcomeRejected); err != nil || got != "ENQUEUED" {
				t.Fatalf("QueueProbeOutcome = %q, %v", got, err)
			}
			if err := s.ClaimControlOutboxOperation("r16-delivery-probe", "probe_outcome", "r16-session"); err != nil {
				t.Fatal(err)
			}
			if err := s.MarkControlOutboxSent("r16-delivery-probe", "probe_outcome", "r16-session"); err != nil {
				t.Fatal(err)
			}
			if state == "SEMANTIC_ACKED" {
				if err := s.AcceptControlSemanticACK("r16-delivery-probe", "probe_outcome", "r16-session"); err != nil {
					t.Fatal(err)
				}
			}
			expired, err := s.ExpireTerminalProbeDeliveriesBeforeLimit(100, 1)
			if err != nil {
				t.Fatal(err)
			}
			if expired != 0 {
				t.Fatalf("expired %d %s deliveries, want 0", expired, state)
			}
			outbox, err := s.ControlOutboxItemByOperation("r16-delivery-probe", "probe_outcome")
			if err != nil {
				t.Fatalf("%s outbox was deleted: %v", state, err)
			}
			if outbox.State != state {
				t.Fatalf("outbox state = %q, want %q", outbox.State, state)
			}
		})
	}
}

func TestR16TerminalDeliveryReceiptMarksDeliveredAtomically(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 83_000)
	if err := s.CreateNode(Node{ID: "node-delivery-r13", Name: "r16-receipt-node"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{
		ID: "r16-receipt-forward", NodeID: "node-delivery-r13", Name: "r16-receipt-forward",
		Protocol: "tcp", CurrentActivationID: "r16-receipt-activation", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	createR13TerminalProbe(t, s, "r16-receipt-probe", "r16-receipt-forward", "r16-receipt-activation", 1)
	if got, err := s.QueueProbeOutcome("r16-receipt-probe", protocol.OutcomeRejected); err != nil || got != "ENQUEUED" {
		t.Fatalf("QueueProbeOutcome = %q, %v", got, err)
	}
	if err := s.ClaimControlOutboxOperation("r16-receipt-probe", "probe_outcome", "r16-session"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkControlOutboxSent("r16-receipt-probe", "probe_outcome", "r16-session"); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptControlSemanticACK("r16-receipt-probe", "probe_outcome", "r16-session"); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptControlReceipt("r16-receipt-probe", "probe_outcome", "r16-session"); err != nil {
		t.Fatal(err)
	}
	disposition, err := s.ProbeOutcomeDisposition("r16-receipt-probe")
	if err != nil {
		t.Fatal(err)
	}
	if disposition != "DELIVERED" {
		t.Fatalf("receipt disposition = %q, want DELIVERED", disposition)
	}
	if _, err := s.ControlOutboxItemByOperation("r16-receipt-probe", "probe_outcome"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("receipted outbox survived: %v", err)
	}
}
