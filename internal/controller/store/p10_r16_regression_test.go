package store

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
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
		1,
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

func TestR16RuntimeStatusRejectsSameActivationAtAdvancedRevision(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 81_500)
	if err := s.CreateNode(Node{ID: "r16-runtime-node", Name: "r16-runtime-node"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{
		ID: "r16-runtime-forward", NodeID: "r16-runtime-node", Name: "r16-runtime-forward",
		Protocol: "tcp", CurrentActivationID: "r16-runtime-activation", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	initial := legalRuntimeSnapshot("NOT_TESTED", "NOT_TESTED", "NONE")
	if err := s.SetForwardRuntimeStatus("r16-runtime-forward", "r16-runtime-activation", 1, initial); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyForwardDelete(ForwardDeletionOperation{
		ID: "r16-runtime-delete", ForwardID: "r16-runtime-forward", Status: "PENDING", DesiredRevision: 1,
	}, ControlOutboxItem{
		OperationID: "r16-runtime-delete", MessageType: "desired", NodeID: "r16-runtime-node", SemanticPayload: `{}`,
	}); err != nil {
		t.Fatal(err)
	}
	advanced := legalRuntimeSnapshot("REJECTED", "FAILED", "NONE")
	if err := s.SetForwardRuntimeStatus("r16-runtime-forward", "r16-runtime-activation", 1, advanced); !errors.Is(err, ErrCASConflict) {
		t.Fatalf("same-activation stale runtime write = %v, want ErrCASConflict", err)
	}
	got, err := s.GetForwardRuntimeStatus("r16-runtime-forward")
	if err != nil {
		t.Fatal(err)
	}
	if got.SnapshotJSON != initial {
		t.Fatalf("stale runtime write changed snapshot to %s", got.SnapshotJSON)
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

func TestR16InboxCleanupRetainsReplayTombstonesUntilHighWater(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 84_000)
	for i, messageType := range []string{"operation_complete", "probe_ingress_receipt", "message_receipt"} {
		messageID := fmt.Sprintf("r16-retained-%d", i)
		if _, err := s.RecordControlInbox(ControlInboxItem{
			MessageID: messageID, NodeID: "r16-node",
			MessageType: messageType, OperationID: fmt.Sprintf("r16-op-%d", i),
			SemanticPayload: `{"ok":true}`, State: "PROCESSED",
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetControlInboxState(messageID, "PROCESSED"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.RecordControlInbox(ControlInboxItem{
		MessageID: "r16-safe-result", NodeID: "r16-node", MessageType: "probe_result",
		OperationID: "r16-safe-op", SemanticPayload: `{}`, State: "PROCESSED",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetControlInboxState("r16-safe-result", "PROCESSED"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE control_inbox SET created_at = 1, updated_at = 1`); err != nil {
		t.Fatal(err)
	}
	removed, err := s.DeleteControlInboxBeforeLimit(84_000, 100)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed %d inbox rows, want only replay-safe probe_result", removed)
	}
	var retained int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM control_inbox WHERE message_type IN ('operation_complete','probe_ingress_receipt','message_receipt')`).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if retained != 3 {
		t.Fatalf("retained replay tombstones = %d, want 3", retained)
	}
}

func TestR16InboxCleanupRetainsProbeResultUntilOutcomeReceipt(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 84_500)
	if err := s.CreateNode(Node{ID: "r16-inbox-node", Name: "r16-inbox-node"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{
		ID: "r16-inbox-forward", NodeID: "r16-inbox-node", Name: "r16-inbox-forward",
		Protocol: "tcp", CurrentActivationID: "r16-inbox-activation", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProbeProvider(ProbeProvider{ID: "provider-r13", Name: "provider-r13"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNode(Node{ID: "node-delivery-r13", Name: "node-delivery-r13"}); err != nil {
		t.Fatal(err)
	}
	createR13TerminalProbe(t, s, "r16-inbox-probe", "r16-inbox-forward", "r16-inbox-activation", 84_000)
	if disposition, err := s.QueueProbeOutcome("r16-inbox-probe", protocol.OutcomeRejected); err != nil || disposition != "ENQUEUED" {
		t.Fatalf("queue probe outcome = %q, %v", disposition, err)
	}
	if _, err := s.RecordControlInbox(ControlInboxItem{
		MessageID: "r16-inbox-result", NodeID: "r16-inbox-node", MessageType: "probe_result",
		OperationID: "r16-inbox-probe", SemanticPayload: `{ "probe_id": "r16-inbox-probe" }`, State: "PROCESSED",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetControlInboxState("r16-inbox-result", "PROCESSED"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE control_inbox SET created_at = 1, updated_at = 1 WHERE message_id = 'r16-inbox-result'`); err != nil {
		t.Fatal(err)
	}
	removed, err := s.DeleteControlInboxBeforeLimit(84_500, 100)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Fatalf("unreceipted probe result cleanup removed %d rows, want 0", removed)
	}

	if err := s.ClaimControlOutboxOperation("r16-inbox-probe", "probe_outcome", "r16-inbox-session"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkControlOutboxSent("r16-inbox-probe", "probe_outcome", "r16-inbox-session"); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptControlSemanticACK("r16-inbox-probe", "probe_outcome", "r16-inbox-session"); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptControlReceipt("r16-inbox-probe", "probe_outcome", "r16-inbox-session"); err != nil {
		t.Fatal(err)
	}
	removed, err = s.DeleteControlInboxBeforeLimit(84_500, 100)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("receipted probe result cleanup removed %d rows, want 1", removed)
	}
}

func TestR16ConcurrentForwardDeleteWritersResolveByCAS(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateNode(Node{ID: "r16-lock-node", Name: "r16-lock-node"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{ID: "r16-lock-forward", NodeID: "r16-lock-node", Name: "r16-lock-forward", Protocol: "tcp", CurrentActivationID: "r16-lock-activation", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	const writers = 32
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			err := s.ApplyForwardDelete(ForwardDeletionOperation{
				ID: fmt.Sprintf("r16-lock-operation-%02d", i), ForwardID: "r16-lock-forward",
				Status: "PENDING", DesiredRevision: 1,
			}, ControlOutboxItem{
				OperationID: fmt.Sprintf("r16-lock-operation-%02d", i), MessageType: "desired",
				NodeID: "r16-lock-node", SemanticPayload: `{}`,
			})
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	succeeded := 0
	for err := range errs {
		if err == nil {
			succeeded++
			continue
		}
		if strings.Contains(err.Error(), "database is locked") || strings.Contains(err.Error(), "SQLITE_BUSY") {
			t.Fatalf("concurrent delete returned lock error: %v", err)
		}
		if !errors.Is(err, ErrCASConflict) {
			t.Fatalf("concurrent delete returned unexpected error: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("concurrent delete successes = %d, want 1", succeeded)
	}
}

func TestR16ForwardDeletionCompletionRequiresExactCorrelation(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 85_000)
	if err := s.CreateNode(Node{ID: "r16-delete-node", Name: "r16-delete-node"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{ID: "r16-delete-forward", NodeID: "r16-delete-node", Name: "r16-delete-forward", Protocol: "tcp", CurrentActivationID: "r16-delete-activation", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	const deletionID = "r16-delete-operation"
	if err := s.ApplyForwardDelete(ForwardDeletionOperation{ID: deletionID, ForwardID: "r16-delete-forward", Status: "PENDING", DesiredRevision: 1}, ControlOutboxItem{OperationID: deletionID, MessageType: "C2A_FORWARD_DELETE", NodeID: "r16-delete-node", SemanticPayload: `{}`}); err != nil {
		t.Fatal(err)
	}
	var resultMessageID, agentOperationID string
	if err := s.db.QueryRow(`SELECT operation_complete_message_id, command_message_id FROM control_outbox WHERE operation_id = ?`, deletionID).Scan(&resultMessageID, &agentOperationID); err != nil {
		t.Fatal(err)
	}
	payload := `{"forward_id":"r16-delete-forward","deletion_operation_id":"r16-delete-operation","deleted":true}`
	if _, err := s.RecordControlInbox(ControlInboxItem{MessageID: resultMessageID, NodeID: "r16-delete-node", MessageType: "operation_complete", OperationID: agentOperationID, SemanticPayload: payload, State: "RECEIVED"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteForwardDeletionResult(resultMessageID, "wrong-operation", "r16-delete-forward"); err == nil {
		t.Fatal("mismatched deletion operation was accepted")
	}
	var status string
	if err := s.db.QueryRow(`SELECT status FROM forward_deletion_operations WHERE id = ?`, deletionID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "PENDING" {
		t.Fatalf("mismatched completion changed status to %q", status)
	}
	if err := s.CompleteForwardDeletionResult(resultMessageID, deletionID, "r16-delete-forward"); err != nil {
		t.Fatalf("exact deletion completion: %v", err)
	}
	if err := s.db.QueryRow(`SELECT status FROM forward_deletion_operations WHERE id = ?`, deletionID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "COMPLETED" {
		t.Fatalf("exact completion status = %q, want COMPLETED", status)
	}
	var inboxState string
	if err := s.db.QueryRow(`SELECT state FROM control_inbox WHERE message_id = ?`, resultMessageID).Scan(&inboxState); err != nil {
		t.Fatal(err)
	}
	if inboxState != "PROCESSED" {
		t.Fatalf("exact completion inbox state = %q, want PROCESSED", inboxState)
	}
	if err := s.CompleteForwardDeletionResult(resultMessageID, deletionID, "r16-delete-forward"); err != nil {
		t.Fatalf("idempotent deletion completion: %v", err)
	}
}

func TestR16ForwardDeletionRecoveryUsesDurableResultCorrelationAfterOutboxGC(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 85_500)
	if err := s.CreateNode(Node{ID: "r16-recovery-node", Name: "r16-recovery-node"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{ID: "r16-recovery-forward", NodeID: "r16-recovery-node", Name: "r16-recovery-forward", Protocol: "tcp", CurrentActivationID: "r16-recovery-activation", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	const deletionID = "r16-recovery-operation"
	if err := s.ApplyForwardDelete(ForwardDeletionOperation{ID: deletionID, ForwardID: "r16-recovery-forward", Status: "PENDING", DesiredRevision: 1}, ControlOutboxItem{OperationID: deletionID, MessageType: "desired", NodeID: "r16-recovery-node", SemanticPayload: `{}`}); err != nil {
		t.Fatal(err)
	}
	var resultMessageID, commandMessageID string
	if err := s.db.QueryRow(`SELECT operation_complete_message_id, command_message_id FROM control_outbox WHERE operation_id = ?`, deletionID).Scan(&resultMessageID, &commandMessageID); err != nil {
		t.Fatal(err)
	}
	payload := `{"forward_id":"r16-recovery-forward","deletion_operation_id":"r16-recovery-operation","deleted":true}`
	if _, err := s.RecordControlInbox(ControlInboxItem{MessageID: resultMessageID, NodeID: "r16-recovery-node", MessageType: "operation_complete", OperationID: commandMessageID, SemanticPayload: payload, State: "RECEIVED"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM control_outbox WHERE operation_id = ?`, deletionID); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteForwardDeletionResult(resultMessageID, deletionID, "r16-recovery-forward"); err != nil {
		t.Fatalf("recovery completion after outbox GC: %v", err)
	}
	var status string
	if err := s.db.QueryRow(`SELECT status FROM forward_deletion_operations WHERE id = ?`, deletionID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "COMPLETED" {
		t.Fatalf("recovered deletion status = %q, want COMPLETED", status)
	}
}

func TestR16ForwardDeletionRecoveryDrainsPast500Rows(t *testing.T) {
	s := openTestStore(t)
	for i := 0; i < 501; i++ {
		messageID := fmt.Sprintf("r16-page-message-%04d", i)
		if _, err := s.RecordControlInbox(ControlInboxItem{
			MessageID: messageID, NodeID: "r16-page-node", MessageType: "operation_complete",
			OperationID: fmt.Sprintf("r16-page-op-%04d", i), SemanticPayload: `{}`, State: "RECEIVED",
		}); err != nil {
			t.Fatal(err)
		}
	}
	processed := 0
	for {
		page, err := s.ListControlInboxByTypeStateLimit("r16-page-node", "RECEIVED", 500, "operation_complete")
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		for _, item := range page {
			if err := s.SetControlInboxState(item.MessageID, "PROCESSED"); err != nil {
				t.Fatal(err)
			}
			processed++
		}
	}
	if processed != 501 {
		t.Fatalf("processed %d deletion results, want 501", processed)
	}
}
