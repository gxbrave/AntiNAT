package agenthub

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// Control channel bounds.
const (
	// sessionTTL bounds a granted session.
	sessionTTL = 24 * time.Hour
	// handshakeTimeout bounds the hello/welcome/final exchange.
	handshakeTimeout = 10 * time.Second
	// maxEnvelopeBytes bounds one WS message (frame + header + payload + sig).
	maxEnvelopeBytes = 13 + protocol.MaxHeaderBytes + protocol.MaxPayloadBytes + 64
	// outboxClaimLimit bounds one outbox pump batch (resource bound).
	outboxClaimLimit = 100
	// sessionIdleTimeout closes a session that sends no frames (heartbeat gap).
	sessionIdleTimeout = 3 * time.Minute
	// outboxPumpInterval is the outbox claim/send cadence.
	outboxPumpInterval = 100 * time.Millisecond
)

// ControlSession is one active Agent control session (one per node).
type ControlSession struct {
	hub      *Hub
	nodeID   string
	epoch    uint64
	session  string
	agentPub ed25519.PublicKey

	conn *websocket.Conn
	mu   sync.Mutex

	// outSeq is the controller's outbound sequence (C2A).
	outSeq uint64
	// inSeq is the last accepted inbound sequence (A2C) per session.
	inSeq uint64

	closed chan struct{}
	once   sync.Once
}

// nodeIDBytes pads the store-form node id to the frozen 16-byte wire width.
func (s *ControlSession) nodeIDBytes() [16]byte {
	var id [16]byte
	copy(id[:], s.nodeID)
	return id
}

// close terminates the session; unregister only goes OFFLINE if no newer
// session took over.
func (s *ControlSession) close() {
	s.once.Do(func() {
		close(s.closed)
		s.conn.CloseNow()
		s.hub.unregister(s)
	})
}

// writeEnvelope signs and writes one C2A envelope with the next sequence.
func (s *ControlSession) writeEnvelope(ctx context.Context, messageID [16]byte, messageType string, payload []byte) error {
	s.mu.Lock()
	s.outSeq++
	seq := s.outSeq
	s.mu.Unlock()

	header := protocol.ProtectedHeader{
		ProtocolDomain:       protocol.ProtocolDomain,
		ControllerInstanceID: s.hub.instanceID(),
		NodeID:               s.nodeIDBytes(),
		ControllerKeyID:      s.hub.keyring.KeyID(),
		AgentCredentialVer:   1,
		ConnectionEpoch:      s.epoch,
		SessionID:            s.session,
		Direction:            protocol.DirectionC2A,
		Sequence:             seq,
		MessageID:            messageID,
		MessageType:          messageType,
		SchemaVersion:        1,
	}
	frame, err := protocol.BuildEnvelope(s.hub.keyring.PrivateKey(), header, payload)
	if err != nil {
		return fmt.Errorf("agenthub: build envelope: %w", err)
	}
	return s.conn.Write(ctx, websocket.MessageBinary, frame)
}

// handleControl upgrades the WebSocket and runs the mutual-challenge
// handshake followed by the frame loop.
func (h *Hub) handleControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // agents are non-browser clients; auth is the signed handshake
	})
	if err != nil {
		return
	}
	conn.SetReadLimit(maxEnvelopeBytes)
	ctx, cancel := context.WithTimeout(r.Context(), handshakeTimeout)
	defer cancel()

	session, err := h.handshake(ctx, conn)
	if err != nil {
		h.audit("CONTROL_HANDSHAKE_REJECTED", fmt.Sprintf(`{"reason":%q}`, err.Error()))
		conn.Close(websocket.StatusPolicyViolation, "handshake rejected")
		return
	}
	h.audit("CONTROL_SESSION_ACTIVE", fmt.Sprintf(`{"node_id":%q,"epoch":%d,"session_id":%q}`, session.nodeID, session.epoch, session.session))
	h.register(session)

	// Outbox pump + inbound frame loop.
	pumpCtx, pumpCancel := context.WithCancel(r.Context())
	defer pumpCancel()
	go h.outboxPump(pumpCtx, session)
	h.frameLoop(r.Context(), session)
	session.close()
	h.audit("CONTROL_SESSION_CLOSED", fmt.Sprintf(`{"node_id":%q,"epoch":%d}`, session.nodeID, session.epoch))
}

// handshake runs SessionHello -> SessionWelcome -> SessionFinal (frozen-style
// mutual challenge; P08-owned wire element).
func (h *Hub) handshake(ctx context.Context, conn *websocket.Conn) (*ControlSession, error) {
	// 1. SessionHello: presented agent key, signature verified against it;
	//    the controller then checks the key hash against the bound credential.
	_, raw, err := conn.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("read hello: %w", err)
	}
	hello, err := security.ParseSessionHello(raw)
	if err != nil {
		return nil, fmt.Errorf("parse hello: %w", err)
	}
	if hello.ProtocolVersions != protocol.EnrollVersion {
		return nil, fmt.Errorf("unsupported protocol version %q", hello.ProtocolVersions)
	}
	if hello.ControllerInstanceID != h.instanceID() {
		return nil, errors.New("hello bound to a different controller instance")
	}
	nodeID := hello.NodeIDString()
	cred, err := h.store.NodeCredentialByNode(nodeID)
	if err != nil {
		return nil, fmt.Errorf("unknown node credential: %w", err)
	}
	wantHash := sha256.Sum256(hello.PublicKey())
	if !stringsEqualFold(cred.PublicKeyHash, hex.EncodeToString(wantHash[:])) {
		return nil, errors.New("agent public key does not match bound credential")
	}

	// 2. Epoch fencing: the agent must not claim an epoch the controller
	//    never issued (rollback/split-brain fails closed).
	node, err := h.store.GetNode(nodeID)
	if err != nil {
		return nil, fmt.Errorf("node lookup: %w", err)
	}
	if hello.AgentMaxEpoch > node.CurrentConnectionEpoch {
		return nil, fmt.Errorf("agent claims epoch %d beyond controller epoch %d (rollback?)", hello.AgentMaxEpoch, node.CurrentConnectionEpoch)
	}
	newSession := randomHexID()
	if err := h.store.CASNodeConnectionEpoch(nodeID, node.CurrentConnectionEpoch, newSession); err != nil {
		return nil, fmt.Errorf("epoch CAS failed: %w", err)
	}
	newEpoch := node.CurrentConnectionEpoch + 1

	// 3. SessionWelcome (signed by the controller key).
	var serverNonce [security.SessionNonceSize]byte
	if _, err := rand.Read(serverNonce[:]); err != nil {
		return nil, err
	}
	welcome := security.SessionWelcome{
		ControllerInstanceID: hello.ControllerInstanceID,
		ControllerKeyID:      h.keyring.KeyID(),
		NodeID:               hello.NodeID,
		AgentNonce:           hello.AgentNonce,
		ServerNonce:          serverNonce,
		ConnectionEpoch:      newEpoch,
		SessionID:            newSession,
		ExpiryUnix:           uint64(h.now() + int64(sessionTTL.Seconds())),
	}
	sig, err := welcome.Sign(h.keyring.PrivateKey())
	if err != nil {
		return nil, err
	}
	rawWelcome := append(welcome.Canonical(), sig...)
	if err := conn.Write(ctx, websocket.MessageBinary, rawWelcome); err != nil {
		return nil, fmt.Errorf("write welcome: %w", err)
	}

	// 4. SessionFinal (signed by the agent key; echoes server nonce + epoch).
	_, rawFinal, err := conn.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("read final: %w", err)
	}
	final, err := security.ParseSessionFinal(rawFinal, hello.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("parse final: %w", err)
	}
	if final.ServerNonce != serverNonce || final.ConnectionEpoch != newEpoch || final.SessionID != newSession {
		return nil, errors.New("session final mismatch")
	}

	return &ControlSession{
		hub:      h,
		nodeID:   nodeID,
		epoch:    newEpoch,
		session:  newSession,
		agentPub: hello.PublicKey(),
		conn:     conn,
		closed:   make(chan struct{}),
	}, nil
}

func stringsEqualFold(a, b string) bool {
	return len(a) == len(b) && (a == b || stringsToLower(a) == stringsToLower(b))
}

func stringsToLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// frameLoop reads and dispatches A2C envelopes until the session closes.
func (h *Hub) frameLoop(ctx context.Context, s *ControlSession) {
	for {
		readCtx, cancel := context.WithTimeout(ctx, sessionIdleTimeout)
		_, frame, err := s.conn.Read(readCtx)
		cancel()
		if err != nil {
			return
		}
		if err := h.handleInboundFrame(s, frame); err != nil {
			h.audit("CONTROL_FRAME_REJECTED", fmt.Sprintf(`{"node_id":%q,"reason":%q}`, s.nodeID, err.Error()))
			return
		}
	}
}

// handleInboundFrame verifies and dispatches one A2C envelope. Any failure
// fails the whole session closed (direction/domain/epoch/session/sequence
// violations are fatal, frozen §3.3/§3.5).
func (h *Hub) handleInboundFrame(s *ControlSession, frame []byte) error {
	env, stage, err := protocol.ParseEnvelope(frame, s.agentPub)
	if err != nil {
		return fmt.Errorf("envelope rejected at %s: %w", stage, err)
	}
	hdr := env.Header
	if hdr.Direction != protocol.DirectionA2C {
		return errors.New("wrong direction: expected A2C")
	}
	if hdr.ConnectionEpoch != s.epoch || hdr.SessionID != s.session {
		return errors.New("stale epoch/session in frame")
	}
	if hdr.NodeID != s.nodeIDBytes() || hdr.AgentCredentialVer == 0 {
		return errors.New("frame node/credential mismatch")
	}
	s.mu.Lock()
	expectedSeq := s.inSeq + 1
	if hdr.Sequence != expectedSeq {
		s.mu.Unlock()
		return fmt.Errorf("sequence %d, want %d", hdr.Sequence, expectedSeq)
	}
	s.inSeq = hdr.Sequence
	s.mu.Unlock()

	switch hdr.MessageType {
	case "desired_result", "operation_complete", "forward_delete_ack",
		"node_decommission_ack", "probe_armed", "probe_ingress_receipt", "probe_result":
		return h.handleAgentResult(s, env)
	case "message_receipt":
		return h.handleAgentReceipt(s, env)
	case "heartbeat", "status":
		return nil // liveness only
	default:
		return fmt.Errorf("unexpected message type %q", hdr.MessageType)
	}
}

// handleAgentResult durably records an A2C semantic result, correlates it to
// the controller outbox row, advances it to SEMANTIC_ACKED (claiming and
// marking sent if the result beat the pump on reconnect), and returns a C2A
// durable receipt so the agent can GC its outbox row.
func (h *Hub) handleAgentResult(s *ControlSession, env protocol.Envelope) error {
	hdr := env.Header
	item := store.ControlInboxItem{
		MessageID:       hex.EncodeToString(hdr.MessageID[:]),
		NodeID:          s.nodeID,
		MessageType:     hdr.MessageType,
		SemanticPayload: string(env.Payload),
		State:           "RECEIVED",
	}
	duplicate, err := h.store.RecordControlInbox(item)
	if err != nil {
		return err
	}
	row, agentOp, err := h.matchOutboxRow(s, hdr.MessageID, hdr.MessageType)
	if err != nil {
		if duplicate {
			return nil // cached duplicate of an already-correlated result
		}
		return err
	}
	// Advance the row to SEMANTIC_ACKED with legal single steps. On reconnect
	// the row may still be PENDING (requeued, pump not yet re-claimed): the
	// result arriving first proves the agent already processed the command,
	// so claim + mark-sent + ack in sequence.
	switch row.State {
	case "PENDING":
		if err := h.store.ClaimControlOutboxOperation(row.OperationID, row.MessageType, s.session); err != nil {
			return err
		}
		if err := h.store.MarkControlOutboxSent(row.OperationID, row.MessageType, s.session); err != nil {
			return err
		}
	case "CLAIMED":
		if err := h.store.MarkControlOutboxSent(row.OperationID, row.MessageType, s.session); err != nil {
			return err
		}
	case "SEMANTIC_ACKED":
		// The result was already processed in an earlier session and the C2A
		// receipt was written, but the connection died before the controller
		// consumed the agent's A2C receipt. The result resend (deduped by
		// deterministic message id) proves the new session is continuing the
		// operation: re-bind the row so the follow-up A2C receipt can
		// complete the GC, skip the FSM advance (no legal step exists past
		// SEMANTIC_ACKED except the receipt), and re-write the idempotent
		// C2A receipt so the agent can GC its own outbox row.
		if err := h.store.RebindControlOutboxSession(row.OperationID, row.MessageType, s.session); err != nil {
			return err
		}
		// SENT rows (result arrived right after the pump's re-send) and any
		// other state fall through: the strict ack below fails closed on
		// states that are not the legal SENT predecessor, exactly as before
		// FIX1.
	}
	if row.State != "SEMANTIC_ACKED" {
		if err := h.store.AcceptControlSemanticACK(row.OperationID, row.MessageType, s.session); err != nil {
			return err
		}
	}
	receiptID := security.MessageID(agentOp, "message_receipt")
	payload := fmt.Sprintf(`{"operation_id":%q}`, agentOp)
	return s.writeEnvelope(context.Background(), receiptID, "message_receipt", []byte(payload))
}

// handleAgentReceipt advances the controller outbox row SEMANTIC_ACKED ->
// RECEIPTED -> GC. A replayed receipt for a row the controller already
// consumed (recorded in control_inbox, outbox row GC'd — the agent resends
// because its C2A receipt was lost) is a cached duplicate: tolerate the
// failed row match idempotently instead of killing the session (mirrors
// handleAgentResult).
func (h *Hub) handleAgentReceipt(s *ControlSession, env protocol.Envelope) error {
	hdr := env.Header
	item := store.ControlInboxItem{
		MessageID:       hex.EncodeToString(hdr.MessageID[:]),
		NodeID:          s.nodeID,
		MessageType:     hdr.MessageType,
		SemanticPayload: string(env.Payload),
		State:           "RECEIVED",
	}
	duplicate, err := h.store.RecordControlInbox(item)
	if err != nil {
		return err
	}
	op, err := operationIDFromReceipt(env.Payload)
	if err != nil {
		return err
	}
	row, _, err := h.matchOutboxRowByCommandMessageID(s, op)
	if err != nil {
		if duplicate {
			return nil // cached duplicate of an already-consumed receipt
		}
		return err
	}
	return h.store.AcceptControlReceipt(row.OperationID, row.MessageType, s.session)
}

// outboxPump claims PENDING rows and sends them as C2A envelopes. A fresh
// session first requeues anything left in flight from a previous session
// (semantic resend, v0.8 §6.1).
func (h *Hub) outboxPump(ctx context.Context, s *ControlSession) {
	if _, err := h.store.RequeueControlOutboxForSession(s.nodeID, s.session); err != nil {
		h.audit("CONTROL_OUTBOX_REQUEUE_FAILED", fmt.Sprintf(`{"node_id":%q,"err":%q}`, s.nodeID, err.Error()))
	}
	ticker := time.NewTicker(outboxPumpInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closed:
			return
		case <-ticker.C:
			items, err := h.store.ClaimControlOutbox(s.nodeID, s.session, outboxClaimLimit)
			if err != nil {
				return
			}
			for _, item := range items {
				msgID := security.MessageID(item.OperationID, item.MessageType)
				if err := s.writeEnvelope(ctx, msgID, item.MessageType, []byte(item.SemanticPayload)); err != nil {
					return
				}
				if err := h.store.MarkControlOutboxSent(item.OperationID, item.MessageType, s.session); err != nil {
					return
				}
			}
		}
	}
}

// register/unregister manage the per-node active session map (one active
// session per node; the new epoch wins). The old session is closed OUTSIDE
// the lock: close() -> unregister() re-enters the map, so holding the lock
// across the close would deadlock.
func (h *Hub) register(s *ControlSession) {
	h.sessionsMu.Lock()
	old := h.sessions[s.nodeID]
	h.sessions[s.nodeID] = s
	h.sessionsMu.Unlock()
	if old != nil {
		old.close()
	}
	if err := h.store.SetNodeControlState(s.nodeID, "ONLINE"); err != nil {
		h.audit("CONTROL_STATE_FAILED", fmt.Sprintf(`{"node_id":%q,"err":%q}`, s.nodeID, err.Error()))
	}
}

func (h *Hub) unregister(s *ControlSession) {
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	if h.sessions[s.nodeID] == s {
		delete(h.sessions, s.nodeID)
		if err := h.store.SetNodeControlState(s.nodeID, "OFFLINE"); err != nil {
			h.audit("CONTROL_STATE_FAILED", fmt.Sprintf(`{"node_id":%q,"err":%q}`, s.nodeID, err.Error()))
		}
	}
}

// ControllerInstanceID returns the raw 16-byte controller instance id.
func (h *Hub) ControllerInstanceID() [16]byte { return h.instanceID() }

// ControllerPublicKey returns the controller signing public key (P10 wires
// this into deployment profiles as the agent's pin source).
func (h *Hub) ControllerPublicKey() ed25519.PublicKey {
	return h.keyring.PublicKey()
}

// ControllerKeyID returns the controller signing key id.
func (h *Hub) ControllerKeyID() string { return h.keyring.KeyID() }

// Keyring returns the controller signing keyring (P10 wires it into app
// composition and deployment profiles).
func (h *Hub) Keyring() *security.Keyring { return h.keyring }

// Challenges exposes the challenge manager (tests + observability).
func (h *Hub) Challenges() *security.ChallengeManager { return h.challenges }

// instanceID returns the raw 16-byte controller instance id.
func (h *Hub) instanceID() [16]byte {
	var out [16]byte
	if s, err := h.store.InstanceID(); err == nil {
		if b, err := hex.DecodeString(s); err == nil && len(b) == 16 {
			copy(out[:], b)
		}
	}
	return out
}

func randomHexID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("agenthub: rand failure") // crypto/rand failure is fatal
	}
	return hex.EncodeToString(b)
}

// matchOutboxRow correlates an agent result envelope to an in-flight outbox
// row and returns the row plus the agent-side operation id used. Candidate A:
// the agent used hex(command message id) as its operation id (inbox FSM).
// Candidate B: the agent used the controller's operation id directly
// (QueueResult path, e.g. deletion results keyed by deletion op id).
// PENDING rows are included so a result that beats the reconnect pump can
// still be correlated (the handler advances the FSM legally).
func (h *Hub) matchOutboxRow(s *ControlSession, resultMsgID [16]byte, resultType string) (store.ControlOutboxItem, string, error) {
	rows, err := h.store.ListControlOutboxByState(s.nodeID, "PENDING", "CLAIMED", "SENT", "SEMANTIC_ACKED")
	if err != nil {
		return store.ControlOutboxItem{}, "", err
	}
	for _, row := range rows {
		cmdMsgID := security.MessageID(row.OperationID, row.MessageType)
		agentOpA := hex.EncodeToString(cmdMsgID[:])
		if security.MessageID(agentOpA, resultType) == resultMsgID {
			return row, agentOpA, nil
		}
		if security.MessageID(row.OperationID, resultType) == resultMsgID {
			return row, row.OperationID, nil
		}
	}
	return store.ControlOutboxItem{}, "", errors.New("agent result does not match any in-flight outbox row")
}

// matchOutboxRowByCommandMessageID correlates an A2C receipt (referencing the
// command message id) to an in-flight row. PENDING rows are included for the
// reconnect race (result/receipt beating the pump).
func (h *Hub) matchOutboxRowByCommandMessageID(s *ControlSession, commandMsgIDHex string) (store.ControlOutboxItem, string, error) {
	rows, err := h.store.ListControlOutboxByState(s.nodeID, "PENDING", "CLAIMED", "SENT", "SEMANTIC_ACKED")
	if err != nil {
		return store.ControlOutboxItem{}, "", err
	}
	for _, row := range rows {
		cmdMsgID := security.MessageID(row.OperationID, row.MessageType)
		if hex.EncodeToString(cmdMsgID[:]) == commandMsgIDHex {
			return row, row.OperationID, nil
		}
	}
	return store.ControlOutboxItem{}, "", errors.New("receipt does not match any in-flight outbox row")
}

// operationIDFromReceipt parses {"operation_id": "..."} from the receipt
// payload.
func operationIDFromReceipt(payload []byte) (string, error) {
	var v struct {
		OperationID string `json:"operation_id"`
	}
	if err := json.Unmarshal(payload, &v); err != nil {
		return "", errors.New("malformed receipt payload")
	}
	if v.OperationID == "" {
		return "", errors.New("receipt payload missing operation_id")
	}
	return v.OperationID, nil
}
