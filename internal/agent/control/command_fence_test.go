// RED for the payload-aware command receive on the live control session: a
// controller-issued desired command carrying an ABSENT Forward must journal
// the payload and durably persist the pending delete fence at RECEIVE time -
// before OnCommand runs - so a crash in the apply pipeline can never
// resurrect the deleted Forward, and an apply failure (NACK) leaves the
// fence in place for the controller's retry.
package control_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/control"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

func TestLegacyRecoveredDeleteRedeliveryConvergesWithoutReplayingCommand(t *testing.T) {
	h := newSessionHarness(t)
	desired := protocol.DesiredState{NodeID: h.nodeID, Forwards: []protocol.ForwardSpec{
		{ForwardID: "fwd-legacy", Protocol: protocol.ProtocolTCP, Target: "10.0.0.1:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresenceAbsent,
			DesiredRevision: 7, DeletionOperationID: "del-legacy"},
		{ForwardID: "fwd-present", Protocol: protocol.ProtocolTCP, Target: "10.0.0.2:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent,
			DesiredRevision: 7},
	}}
	raw, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "op-legacy", MessageType: "desired", NodeID: h.nodeID,
		SemanticPayload: string(raw), State: "PENDING",
	}); err != nil {
		t.Fatal(err)
	}

	// Seed the exact pre-upgrade state before connecting: the old receive path
	// knows only the payload hash and the operation crashed in APPLYING. The
	// handshake must recover C to NACKED before the frame can be redelivered.
	commandID := security.MessageID("op-legacy", "desired")
	opID := hex.EncodeToString(commandID[:])
	sum := sha256.Sum256(raw)
	if duplicate, err := h.ls.ReceiveCommand(0, "", opID, opID, "desired", hex.EncodeToString(sum[:]), "desired"); err != nil || duplicate {
		t.Fatalf("legacy receive duplicate=%v err=%v", duplicate, err)
	}
	if err := h.ls.PersistOperationIntent(0, "", opID); err != nil {
		t.Fatal(err)
	}
	if err := h.ls.MarkOperationApplying(0, "", opID); err != nil {
		t.Fatal(err)
	}

	var normalApply atomic.Int32
	var cleanup atomic.Int32
	client, err := control.NewClient(control.ClientOptions{
		Endpoint: h.srv.URL, NodeID: h.nodeID, Store: h.ls, Key: h.key,
		Heartbeat: 50 * time.Millisecond,
		OnCommand: func(context.Context, control.Operation) ([]byte, error) {
			normalApply.Add(1)
			return nil, nil
		},
		OnRecoveredDeletion: func(_ context.Context, op control.Operation) error {
			cleanup.Add(1)
			var got protocol.DesiredState
			if err := protocol.DecodeStrictJSONInto(op.Payload, &got); err != nil {
				return err
			}
			if len(got.Forwards) != 2 {
				t.Fatalf("recovered payload forwards=%d, want exact mixed snapshot", len(got.Forwards))
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	deadline := time.Now().Add(8 * time.Second)
	for cleanup.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := cleanup.Load(); got != 1 {
		t.Fatalf("recovered deletion callbacks=%d, want 1", got)
	}
	if got := normalApply.Load(); got != 0 {
		t.Fatalf("legacy recovered command replayed normal apply %d times", got)
	}
	intent, ok, err := h.ls.GetForwardDeleteIntent("fwd-legacy")
	if err != nil || !ok || intent.DeletionOperationID != "del-legacy" {
		t.Fatalf("legacy redelivery fence ok=%v err=%v intent=%+v", ok, err, intent)
	}
	if h.ls.OutboxContains("del-legacy") {
		t.Fatal("control recovery fabricated D result before deletion cleanup")
	}
}

func TestCommandReceivePersistsDeleteFenceBeforeApply(t *testing.T) {
	h := newSessionHarness(t)

	desired := protocol.DesiredState{NodeID: h.nodeID, Forwards: []protocol.ForwardSpec{
		{ForwardID: "fwd-fence", Protocol: protocol.ProtocolTCP, Target: "10.0.0.1:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresenceAbsent,
			DesiredRevision: 3, DeletionOperationID: "del-fence"},
	}}
	raw, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.st.EnqueueControlOutbox(store.ControlOutboxItem{
		OperationID: "op-fence", MessageType: "desired", NodeID: h.nodeID,
		SemanticPayload: string(raw), State: "PENDING",
	}); err != nil {
		t.Fatal(err)
	}

	applied := make(chan control.Operation, 4)
	client, err := control.NewClient(control.ClientOptions{
		Endpoint: h.srv.URL, NodeID: h.nodeID, Store: h.ls, Key: h.key,
		Heartbeat: 50 * time.Millisecond,
		OnCommand: func(ctx context.Context, op control.Operation) ([]byte, error) {
			applied <- op
			// Simulate an apply-pipeline failure: the command NACKs, but the
			// deletion fence must already be durable from the receive path.
			return nil, context.DeadlineExceeded
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	select {
	case op := <-applied:
		if op.MessageType != "desired" {
			t.Fatalf("delivered command type=%q, want desired", op.MessageType)
		}
		var d protocol.DesiredState
		if err := protocol.DecodeStrictJSONInto(op.Payload, &d); err != nil {
			t.Fatalf("delivered payload decode: %v", err)
		}
		if len(d.Forwards) != 1 || d.Forwards[0].ForwardID != "fwd-fence" {
			t.Fatalf("delivered payload=%+v, want the ABSENT fwd-fence snapshot", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("desired command was never delivered to the agent")
	}

	// The fence is durable even though the apply pipeline failed.
	intent, ok, err := h.ls.GetForwardDeleteIntent("fwd-fence")
	if err != nil || !ok {
		t.Fatalf("pending delete fence after failed apply ok=%v err=%v", ok, err)
	}
	if intent.DeletionOperationID != "del-fence" || intent.DesiredRevision != 3 {
		t.Fatalf("fence identity=%+v, want del-fence/3", intent)
	}
}
