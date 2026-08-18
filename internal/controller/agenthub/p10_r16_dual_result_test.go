package agenthub_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

func readC2AType(t *testing.T, conn *rawAgentConn, ctx context.Context, messageType string) protocol.Envelope {
	t.Helper()
	for {
		_, raw, err := conn.conn.Read(ctx)
		if err != nil {
			events, _ := conn.st.AdminEventsAfter(0, 100)
			t.Fatalf("read C2A %s: %v; admin events: %+v", messageType, err, events)
		}
		env, _, err := protocol.ParseEnvelope(raw, conn.hub.ControllerPublicKey())
		if err != nil {
			t.Fatalf("parse C2A %s: %v", messageType, err)
		}
		if env.Header.MessageType == messageType {
			return env
		}
	}
}

// R16 RED: a desired forward deletion produces two agent result outbox rows.
// The controller must receipt both rows without treating the second result's
// agent operation id (the deletion id) as a C2A command message id.
func TestForwardDeleteControllerReceiptsBothAgentResults(t *testing.T) {
	hub, st, srv := newFencedHub(t)
	const nodeID = "node-del-r16"
	if err := st.CreateNode(store.Node{ID: nodeID, Name: nodeID}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateForward(store.Forward{
		ID: "forward-delete-receipt", NodeID: nodeID, Name: "delete-receipt",
		Protocol: "tcp", CurrentActivationID: "activation-delete-receipt", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	const deletionID = "deletion-receipt-operation"
	if err := st.ApplyForwardDelete(store.ForwardDeletionOperation{
		ID: deletionID, ForwardID: "forward-delete-receipt", Status: "PENDING", DesiredRevision: 1,
	}, store.ControlOutboxItem{
		OperationID: deletionID, MessageType: "desired", NodeID: nodeID, SemanticPayload: `{}`,
	}); err != nil {
		t.Fatal(err)
	}
	key := enrollRaw(t, hub, st, nodeID)
	conn := dialRawAgent(t, hub, st, srv, nodeID, key)
	defer conn.conn.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	command := readC2AType(t, conn, ctx, "desired")
	agentOperationID := hex.EncodeToString(command.Header.MessageID[:])
	firstResultID := security.MessageID(agentOperationID, "operation_complete")
	if err := sendA2CExact(ctx, conn, 1, firstResultID, "operation_complete", []byte(`{"status":"applied"}`)); err != nil {
		t.Fatal(err)
	}
	_ = readC2AType(t, conn, ctx, "message_receipt")
	firstReceiptID := security.MessageID(agentOperationID, "message_receipt")
	if err := sendA2CExact(ctx, conn, 2, firstReceiptID, "message_receipt", []byte(fmt.Sprintf(`{"operation_id":%q}`, agentOperationID))); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ControlOutboxItemByOperation(deletionID, "desired"); err != nil {
		t.Fatalf("controller deletion outbox was GC'd after first result: %v", err)
	}

	secondResultID := security.MessageID(deletionID, "operation_complete")
	secondPayload := []byte(`{"forward_id":"forward-delete-receipt","deletion_operation_id":"deletion-receipt-operation","deleted":true}`)
	if err := sendA2CExact(ctx, conn, 3, secondResultID, "operation_complete", secondPayload); err != nil {
		t.Fatal(err)
	}
	_ = readC2AType(t, conn, ctx, "message_receipt")
	secondReceiptID := security.MessageID(deletionID, "message_receipt")
	if err := sendA2CExact(ctx, conn, 4, secondReceiptID, "message_receipt", []byte(fmt.Sprintf(`{"operation_id":%q}`, deletionID))); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := st.ControlOutboxItemByOperation(deletionID, "desired"); errors.Is(err, store.ErrNotFound) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := st.ControlOutboxItemByOperation(deletionID, "desired"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("controller deletion outbox survived both result receipts: %v", err)
	}
	if err := sendA2CExact(ctx, conn, 5, security.MessageID("delete-receipt-heartbeat", "heartbeat"), "heartbeat", []byte(`{}`)); err != nil {
		t.Fatalf("session closed while consuming second result receipt: %v", err)
	}
}
