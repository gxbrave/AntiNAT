package store

import (
	"errors"
	"testing"
)

// Transport dispositions deliberately project the frozen generic inbox FSM:
// PROCESSED is successful downstream application, while NACKED is a terminal
// negative disposition. Neither path may skip from a non-RECEIVED transport
// row, and probe-operation REJECTED is not a control-inbox state.
func TestControlInboxTransportDispositionTransitionsAreStrict(t *testing.T) {
	s := openControlStore(t)
	item := ControlInboxItem{
		MessageID: "disposition-message", NodeID: "disposition-node",
		MessageType: "probe_ingress_receipt", OperationID: "disposition-op",
		SemanticPayload: "receipt",
	}
	if duplicate, err := s.RecordControlInbox(item); err != nil || duplicate {
		t.Fatalf("record inbox = duplicate:%v err:%v", duplicate, err)
	}
	if got, err := s.ControlInboxState(item.MessageID); err != nil || got != ControlInboxReceived {
		t.Fatalf("initial state = %q err=%v, want RECEIVED", got, err)
	}
	if err := s.SetControlInboxState(item.MessageID, ControlInboxProcessed); err != nil {
		t.Fatalf("RECEIVED -> PROCESSED: %v", err)
	}
	if err := s.SetControlInboxState(item.MessageID, ControlInboxNacked); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("PROCESSED -> NACKED = %v, want ErrIllegalPhase", err)
	}
	if err := s.SetControlInboxState(item.MessageID, ControlInboxProcessed); err != nil {
		t.Fatalf("idempotent PROCESSED = %v", err)
	}

	negative := item
	negative.MessageID = "disposition-negative"
	if duplicate, err := s.RecordControlInbox(negative); err != nil || duplicate {
		t.Fatalf("record negative inbox = duplicate:%v err:%v", duplicate, err)
	}
	if err := s.RejectControlInbox(negative.MessageID); err != nil {
		t.Fatalf("RECEIVED -> NACKED: %v", err)
	}
	if err := s.RejectControlInbox(negative.MessageID); err != nil {
		t.Fatalf("idempotent NACKED: %v", err)
	}
	if err := s.SetControlInboxState(negative.MessageID, ControlInboxProcessed); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("NACKED -> PROCESSED = %v, want ErrIllegalPhase", err)
	}
}

func TestControlInboxTransportRejectsUnknownDisposition(t *testing.T) {
	s := openControlStore(t)
	item := ControlInboxItem{MessageID: "disposition-unknown", NodeID: "n", MessageType: "probe_result", SemanticPayload: "{}"}
	if _, err := s.RecordControlInbox(item); err != nil {
		t.Fatal(err)
	}
	if err := s.SetControlInboxState(item.MessageID, "REJECTED"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("unknown transport disposition = %v, want ErrIllegalPhase", err)
	}
	if got, err := s.ControlInboxState(item.MessageID); err != nil || got != ControlInboxReceived {
		t.Fatalf("unknown disposition changed state to %q (err %v)", got, err)
	}
}
