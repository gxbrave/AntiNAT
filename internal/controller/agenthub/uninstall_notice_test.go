package agenthub

import (
	"testing"

	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

func TestParseAgentUninstallNoticeRequiresExactPayloadAndMessageBinding(t *testing.T) {
	const operationID = "0123456789abcdef0123456789abcdef"
	valid := protocol.Envelope{
		Header:  protocol.ProtectedHeader{MessageID: security.MessageID(operationID, "operation_complete")},
		Payload: []byte(`{"deletion_operation_id":"` + operationID + `","notice":"agent uninstall requested"}`),
	}
	if got, ok := parseAgentUninstallNotice(valid); !ok || got != operationID {
		t.Fatalf("valid notice = %q, %v", got, ok)
	}

	tests := map[string]protocol.Envelope{
		"unbound message id": {
			Header:  protocol.ProtectedHeader{MessageID: security.MessageID("different", "operation_complete")},
			Payload: valid.Payload,
		},
		"unknown field": {
			Header:  valid.Header,
			Payload: []byte(`{"deletion_operation_id":"` + operationID + `","notice":"agent uninstall requested","extra":true}`),
		},
		"wrong notice": {
			Header:  valid.Header,
			Payload: []byte(`{"deletion_operation_id":"` + operationID + `","notice":"other"}`),
		},
		"non-canonical operation": {
			Header:  valid.Header,
			Payload: []byte(`{"deletion_operation_id":"ABCDEF0123456789ABCDEF0123456789","notice":"agent uninstall requested"}`),
		},
	}
	for name, envelope := range tests {
		t.Run(name, func(t *testing.T) {
			if got, ok := parseAgentUninstallNotice(envelope); ok || got != "" {
				t.Fatalf("invalid notice = %q, %v", got, ok)
			}
		})
	}
}
