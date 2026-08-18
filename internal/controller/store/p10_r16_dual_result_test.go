package store

import (
	"errors"
	"fmt"
	"testing"
)

func TestR16ForwardDeleteOutboxWaitsForBothSemanticResults(t *testing.T) {
	s := openTestStore(t)
	withStoreNow(t, 83_500)
	if err := s.CreateNode(Node{ID: "r16-dual-node", Name: "r16-dual-node"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateForward(Forward{
		ID: "r16-dual-forward", NodeID: "r16-dual-node", Name: "r16-dual-forward",
		Protocol: "tcp", CurrentActivationID: "r16-dual-activation", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	const deletionID = "r16-dual-delete"
	if err := s.ApplyForwardDelete(ForwardDeletionOperation{
		ID: deletionID, ForwardID: "r16-dual-forward", Status: "PENDING", DesiredRevision: 1,
	}, ControlOutboxItem{
		OperationID: deletionID, MessageType: "desired", NodeID: "r16-dual-node", SemanticPayload: `{}`,
	}); err != nil {
		t.Fatal(err)
	}
	var commandID, agentResultID, controllerResultID string
	if err := s.db.QueryRow(`SELECT command_message_id, operation_complete_message_id, controller_operation_complete_message_id
		FROM control_outbox WHERE operation_id = ?`, deletionID).Scan(&commandID, &agentResultID, &controllerResultID); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimControlOutboxOperation(deletionID, "desired", "r16-dual-session"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkControlOutboxSent(deletionID, "desired", "r16-dual-session"); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptControlSemanticACK(deletionID, "desired", "r16-dual-session"); err != nil {
		t.Fatal(err)
	}
	// The normal desired command result arrives first. Its durable receipt
	// must not GC the controller row before the separate deletion result can
	// be correlated and delivered.
	if _, err := s.RecordControlInbox(ControlInboxItem{
		MessageID: agentResultID, NodeID: "r16-dual-node", MessageType: "operation_complete",
		OperationID: commandID, SemanticPayload: `{"Status":0,"Results":[]}`, State: "PROCESSED",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordControlInbox(ControlInboxItem{
		MessageID: "r16-dual-receipt-1", NodeID: "r16-dual-node", MessageType: "message_receipt",
		OperationID: commandID, SemanticPayload: fmt.Sprintf(`{"operation_id":%q}`, commandID), State: "PROCESSED",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptControlReceipt(deletionID, "desired", "r16-dual-session"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ControlOutboxItemByOperation(deletionID, "desired"); err != nil {
		t.Fatalf("outbox was GC'd after only the command result: %v", err)
	}

	if _, err := s.RecordControlInbox(ControlInboxItem{
		MessageID: controllerResultID, NodeID: "r16-dual-node", MessageType: "operation_complete",
		OperationID: deletionID, SemanticPayload: `{"forward_id":"r16-dual-forward","deletion_operation_id":"r16-dual-delete","deleted":true}`, State: "PROCESSED",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordControlInbox(ControlInboxItem{
		MessageID: "r16-dual-receipt-2", NodeID: "r16-dual-node", MessageType: "message_receipt",
		OperationID: deletionID, SemanticPayload: fmt.Sprintf(`{"operation_id":%q}`, deletionID), State: "PROCESSED",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptControlReceipt(deletionID, "desired", "r16-dual-session"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ControlOutboxItemByOperation(deletionID, "desired"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("outbox survived both semantic receipts: %v", err)
	}
}
