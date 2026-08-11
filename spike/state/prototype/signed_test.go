package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

// Story 3 two-sided signed-command coverage (SPEC F2 / QUALITY Q4). Distinct
// Controller and Agent stores exchange domain-separated Ed25519-signed
// commands and ACKs. Stale signed commands must be rejected on BOTH sides,
// and tampered, wrong-key, wrong-direction, and replayed envelopes must fail
// closed. Written before the signed-envelope prototype existed; it failed
// (symbols absent) and now passes against the implementation.

const (
	controllerID = "controller-1"
	agentID      = "agent-1"
)

func newTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("unexpected public key size %d", len(pub))
	}
	return priv
}

func setupTwoSided(t *testing.T) (controller, agent *Store, controllerPriv, agentPriv ed25519.PrivateKey) {
	t.Helper()
	var err error
	controller, err = OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	agent, err = OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		controller.Close()
		agent.Close()
	})
	controllerPriv = newTestKey(t)
	agentPriv = newTestKey(t)
	if err := controller.AdvanceSession(7, "session-7"); err != nil {
		t.Fatal(err)
	}
	if err := agent.AdvanceSession(7, "session-7"); err != nil {
		t.Fatal(err)
	}
	return controller, agent, controllerPriv, agentPriv
}

func signCommand(t *testing.T, priv ed25519.PrivateKey, direction string, epoch uint64, sessionID string, sequence uint64, messageID, messageType, payload string) *SignedMessage {
	t.Helper()
	message := NewSignedMessage(direction, epoch, sessionID, sequence, messageID, messageType, payload)
	if err := message.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return message
}

func TestValidSignedCommandAcceptedOnAgentAndACKOnController(t *testing.T) {
	controller, agent, controllerPriv, agentPriv := setupTwoSided(t)
	command := signCommand(t, controllerPriv, DirectionControllerToAgent, 7, "session-7", 1, "message-1", "apply", "desired-state")
	if _, err := DeliverSigned(agent, controllerPriv.Public().(ed25519.PublicKey), DirectionControllerToAgent, command); err != nil {
		t.Fatalf("agent rejected a valid signed command: %v", err)
	}
	ack := signCommand(t, agentPriv, DirectionAgentToController, 7, "session-7", 1, "ack-1", "applied", "APPLIED")
	if _, err := DeliverSigned(controller, agentPriv.Public().(ed25519.PublicKey), DirectionAgentToController, ack); err != nil {
		t.Fatalf("controller rejected a valid signed ACK: %v", err)
	}
}

func TestTamperedPayloadRejectedOnAgentSide(t *testing.T) {
	_, agent, controllerPriv, _ := setupTwoSided(t)
	command := signCommand(t, controllerPriv, DirectionControllerToAgent, 7, "session-7", 1, "message-1", "apply", "desired-state")
	command.Payload = "tampered-state" // changes payload but not the signed hash
	if _, err := DeliverSigned(agent, controllerPriv.Public().(ed25519.PublicKey), DirectionControllerToAgent, command); err == nil {
		t.Fatal("agent accepted a tampered signed command; want fail closed")
	}
}

func TestInvalidSignatureRejectedOnBothSides(t *testing.T) {
	controller, agent, controllerPriv, _ := setupTwoSided(t)
	command := signCommand(t, controllerPriv, DirectionControllerToAgent, 7, "session-7", 1, "message-1", "apply", "desired-state")
	command.Signature[0] ^= 0xff
	if _, err := DeliverSigned(agent, controllerPriv.Public().(ed25519.PublicKey), DirectionControllerToAgent, command); err == nil {
		t.Fatal("agent accepted a corrupted signature; want fail closed")
	}
	ack := signCommand(t, controllerPriv, DirectionAgentToController, 7, "session-7", 1, "ack-1", "applied", "APPLIED")
	ack.Signature[0] ^= 0xff
	if _, err := DeliverSigned(controller, controllerPriv.Public().(ed25519.PublicKey), DirectionAgentToController, ack); err == nil {
		t.Fatal("controller accepted a corrupted signature; want fail closed")
	}
}

func TestWrongKeyRejectedOnAgentSide(t *testing.T) {
	_, agent, controllerPriv, _ := setupTwoSided(t)
	intruder := newTestKey(t)
	command := signCommand(t, intruder, DirectionControllerToAgent, 7, "session-7", 1, "message-1", "apply", "desired-state")
	// The agent pins the real controller key; a command signed by any other
	// key must fail verification against the pinned key.
	if _, err := DeliverSigned(agent, controllerPriv.Public().(ed25519.PublicKey), DirectionControllerToAgent, command); err == nil {
		t.Fatal("agent accepted a command not signed by the pinned controller key; want fail closed")
	}
}

func TestWrongDirectionRejected(t *testing.T) {
	controller, agent, controllerPriv, _ := setupTwoSided(t)
	command := signCommand(t, controllerPriv, DirectionControllerToAgent, 7, "session-7", 1, "message-1", "apply", "desired-state")
	// Present a controller->agent command as if it were an agent->controller ACK.
	if _, err := DeliverSigned(controller, controllerPriv.Public().(ed25519.PublicKey), DirectionAgentToController, command); err == nil {
		t.Fatal("controller accepted a wrong-direction envelope; want fail closed")
	}
	if _, err := DeliverSigned(agent, controllerPriv.Public().(ed25519.PublicKey), DirectionControllerToAgent, command); err != nil {
		t.Fatalf("valid direction envelope unexpectedly rejected: %v", err)
	}
}

func TestStaleSignedCommandRejectedOnBothSides(t *testing.T) {
	controller, agent, controllerPriv, agentPriv := setupTwoSided(t)
	// Both sides move to a new epoch/session.
	if err := controller.AdvanceSession(8, "session-8"); err != nil {
		t.Fatal(err)
	}
	if err := agent.AdvanceSession(8, "session-8"); err != nil {
		t.Fatal(err)
	}
	// A stale signed command (epoch 7, session-7) must be rejected on the agent.
	staleCommand := signCommand(t, controllerPriv, DirectionControllerToAgent, 7, "session-7", 2, "message-stale", "apply", "stale")
	if _, err := DeliverSigned(agent, controllerPriv.Public().(ed25519.PublicKey), DirectionControllerToAgent, staleCommand); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("agent accepted a stale signed command (err=%v); want ErrStaleSession", err)
	}
	// A stale signed ACK (epoch 7, session-7) must be rejected on the controller.
	staleACK := signCommand(t, agentPriv, DirectionAgentToController, 7, "session-7", 2, "ack-stale", "applied", "APPLIED")
	if _, err := DeliverSigned(controller, agentPriv.Public().(ed25519.PublicKey), DirectionAgentToController, staleACK); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("controller accepted a stale signed ACK (err=%v); want ErrStaleSession", err)
	}
}

func TestReplayedSignedCommandRejectedOnBothSides(t *testing.T) {
	controller, agent, controllerPriv, agentPriv := setupTwoSided(t)
	command := signCommand(t, controllerPriv, DirectionControllerToAgent, 7, "session-7", 1, "message-1", "apply", "desired-state")
	if _, err := DeliverSigned(agent, controllerPriv.Public().(ed25519.PublicKey), DirectionControllerToAgent, command); err != nil {
		t.Fatal(err)
	}
	duplicate, err := DeliverSigned(agent, controllerPriv.Public().(ed25519.PublicKey), DirectionControllerToAgent, command)
	if err != nil {
		t.Fatalf("identical re-delivery errored: %v", err)
	}
	if !duplicate {
		t.Fatal("replayed signed command was not detected as a duplicate on the agent")
	}

	ack := signCommand(t, agentPriv, DirectionAgentToController, 7, "session-7", 1, "ack-1", "applied", "APPLIED")
	if _, err := DeliverSigned(controller, agentPriv.Public().(ed25519.PublicKey), DirectionAgentToController, ack); err != nil {
		t.Fatal(err)
	}
	duplicate, err = DeliverSigned(controller, agentPriv.Public().(ed25519.PublicKey), DirectionAgentToController, ack)
	if err != nil {
		t.Fatalf("identical replayed ACK errored: %v", err)
	}
	if !duplicate {
		t.Fatal("replayed signed ACK was not detected as a duplicate on the controller")
	}
}

func TestConflictingSignedReplayFailsClosed(t *testing.T) {
	_, agent, controllerPriv, _ := setupTwoSided(t)
	first := signCommand(t, controllerPriv, DirectionControllerToAgent, 7, "session-7", 1, "message-1", "apply", "desired-state")
	if _, err := DeliverSigned(agent, controllerPriv.Public().(ed25519.PublicKey), DirectionControllerToAgent, first); err != nil {
		t.Fatal(err)
	}
	conflict := signCommand(t, controllerPriv, DirectionControllerToAgent, 7, "session-7", 1, "message-1", "apply", "different-payload")
	if _, err := DeliverSigned(agent, controllerPriv.Public().(ed25519.PublicKey), DirectionControllerToAgent, conflict); !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("conflicting replay error = %v, want ErrMessageConflict", err)
	}
}
