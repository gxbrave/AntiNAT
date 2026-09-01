package agenthub

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/gxbrave/AntiNAT/internal/controller/lifecycle"
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
	owner    store.ControlOwner
	agentPub ed25519.PublicKey

	conn    *websocket.Conn
	mu      sync.Mutex
	writeMu sync.Mutex

	// cleanupOnly marks a force-deleted node's restricted session (P14 Story 3):
	// only the terminal ACK/status/heartbeat channels are permitted.
	cleanupOnly bool

	// outSeq is the controller's outbound sequence (C2A).
	outSeq uint64
	// inSeq is the last accepted inbound sequence (A2C) per session.
	inSeq uint64

	closed   chan struct{}
	once     sync.Once
	done     chan struct{}
	doneOnce sync.Once
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

func (s *ControlSession) markDone() {
	if s.done != nil {
		s.doneOnce.Do(func() { close(s.done) })
	}
}

func (s *ControlSession) wait() {
	if s.done != nil {
		<-s.done
	}
}

// writeEnvelope signs and writes one C2A envelope with the next sequence.
// Sequence reservation happens only after local envelope preparation succeeds;
// a malformed payload or an unavailable connection must not create a gap in an
// otherwise-live session.
func (s *ControlSession) writeEnvelope(ctx context.Context, messageID [16]byte, messageType string, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.mu.Lock()
	conn := s.conn
	seq := s.outSeq + 1
	s.mu.Unlock()
	if conn == nil {
		return errors.New("agenthub: session is not connected")
	}

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

	// writeMu excludes every other writer, but retain the CAS-style check so a
	// future caller cannot publish a frame with a sequence that was consumed
	// while this envelope was being prepared.
	s.mu.Lock()
	if s.outSeq+1 != seq {
		s.mu.Unlock()
		return errors.New("agenthub: outbound sequence changed during envelope preparation")
	}
	s.outSeq = seq
	s.mu.Unlock()
	return conn.Write(ctx, websocket.MessageBinary, frame)
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
	if !h.beginHandshake(conn) {
		conn.CloseNow()
		return
	}
	defer h.endHandshake(conn)
	conn.SetReadLimit(maxEnvelopeBytes)
	ctx, cancel := context.WithTimeout(r.Context(), handshakeTimeout)
	defer cancel()

	session, err := h.handshake(ctx, conn)
	if err != nil {
		h.audit("CONTROL_HANDSHAKE_REJECTED", fmt.Sprintf(`{"reason":%q}`, err.Error()))
		conn.Close(websocket.StatusPolicyViolation, "handshake rejected")
		return
	}
	defer session.markDone()
	if !h.register(session) {
		return
	}
	h.audit("CONTROL_SESSION_ACTIVE", fmt.Sprintf(`{"node_id":%q,"epoch":%d,"session_id":%q}`, session.nodeID, session.epoch, session.session))

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
	owner, err := h.store.AcquireControlOwner(nodeID, node.CurrentConnectionEpoch, newSession)
	if err != nil {
		return nil, fmt.Errorf("epoch CAS failed: %w", err)
	}
	newEpoch := owner.ConnectionEpoch

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

	cleanupOnly, _ := h.store.IsCleanupOnly(nodeID)
	return &ControlSession{
		hub:         h,
		nodeID:      nodeID,
		epoch:       newEpoch,
		session:     newSession,
		owner:       owner,
		agentPub:    hello.PublicKey(),
		conn:        conn,
		cleanupOnly: cleanupOnly,
		closed:      make(chan struct{}),
		done:        make(chan struct{}),
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
	// P14 Story 3 restricted session: a cleanup-only node may only deliver the
	// terminal decommission ACK and status/heartbeat/operation frames. Any other
	// inbound material is rejected fail-closed (the issuer never legitimately
	// sent desired/secrets, because the enqueue guard refused them).
	if s.cleanupOnly && !lifecycle.AllowedInboundCleanupOnly(hdr.MessageType) {
		return fmt.Errorf("cleanup-only node refused inbound message type %q", hdr.MessageType)
	}
	if hdr.ConnectionEpoch != s.epoch || hdr.SessionID != s.session {
		return errors.New("stale epoch/session in frame")
	}
	if hdr.NodeID != s.nodeIDBytes() || hdr.AgentCredentialVer == 0 {
		return errors.New("frame node/credential mismatch")
	}
	// The frame may have been parsed before a takeover. Recheck the durable
	// owner immediately before sequence advancement and downstream mutation;
	// each owner-aware store write repeats the predicate atomically.
	if err := h.store.RequireCurrentControlOwner(s.owner); err != nil {
		return err
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
		"node_decommission_ack":
		return h.handleAgentResult(s, env)
	case "probe_armed", "probe_ingress_receipt", "probe_result":
		return h.handleProbePlaneMessage(s, env)
	case "message_receipt":
		return h.handleAgentReceipt(s, env)
	case "heartbeat":
		return nil
	case "status":
		if sink, ok := h.sink.(ActivationStatusSink); ok {
			if err := sink.HandleActivationStatus(s.nodeID, env.Payload); err != nil {
				var stale interface{ StaleActivationStatus() bool }
				if errors.As(err, &stale) && stale.StaleActivationStatus() {
					h.audit("CONTROL_STATUS_STALE", fmt.Sprintf(`{"node_id":%q,"reason":%q}`, s.nodeID, err.Error()))
					return nil
				}
				return err
			}
		}
		return nil // liveness only
	default:
		return fmt.Errorf("unexpected message type %q", hdr.MessageType)
	}
}

// A sink can authorize terminal probe-receipt rejection only through an
// explicit marker. Generic parser or store sentinels may also describe
// retryable/internal failures when returned by another sink implementation.
func isPermanentProbeReceiptError(err error) bool {
	var marker interface{ PermanentProbeReceipt() bool }
	return errors.As(err, &marker) && marker.PermanentProbeReceipt()
}

// recordProbeReceiptInbox preserves the legacy empty-operation binding used by
// older control-inbox rows. The payload-derived operation id is authoritative
// only after the authenticated message material and node/type binding match.
func (h *Hub) recordProbeReceiptInbox(s *ControlSession, item store.ControlInboxItem) (bool, error) {
	duplicate, err := h.store.RecordControlInboxOwned(s.owner, item)
	if err == nil {
		return duplicate, nil
	}
	if !errors.Is(err, store.ErrMessageConflict) {
		return false, err
	}
	existing, getErr := h.store.ControlInboxItemByMessageID(item.MessageID)
	if getErr != nil {
		return false, err
	}
	if existing.NodeID != item.NodeID || existing.MessageType != item.MessageType ||
		existing.SemanticPayload != item.SemanticPayload ||
		(existing.OperationID != "" && existing.OperationID != item.OperationID) {
		return false, err
	}
	if existing.OperationID == "" {
		if bindErr := h.store.BindControlInboxOperationIDOwned(s.owner, item.MessageID, item.OperationID); bindErr != nil {
			return false, bindErr
		}
	}
	return true, nil
}

// processProbeReceipt runs the durable RCT1 sink boundary. The keyed delivery
// lock is held across admission, sink execution, and exact completion: closing
// an old WebSocket does not stop a handler already inside the sink, and a
// takeover must not let a replacement handler invoke the same sink twice.
// Retryable failures deliberately leave the inbox row RECEIVED for replay.
func (h *Hub) processProbeReceipt(s *ControlSession, item store.ControlInboxItem) (bool, error) {
	unlock := h.probeDeliveryLocks.acquire(item.MessageID)
	defer unlock()
	duplicate, err := h.recordProbeReceiptInbox(s, item)
	if err != nil {
		if errors.Is(err, store.ErrMessageConflict) {
			return false, err
		}
		h.audit("PROBE_RECEIPT_INBOX_ERROR", fmt.Sprintf(`{"node_id":%q,"err":%q}`, s.nodeID, err.Error()))
		return false, nil
	}
	_ = duplicate
	state, err := h.store.ControlInboxState(item.MessageID)
	if err != nil {
		h.audit("PROBE_RECEIPT_STATE_ERROR", fmt.Sprintf(`{"node_id":%q,"err":%q}`, s.nodeID, err.Error()))
		return false, nil
	}
	if state == store.ControlInboxProcessed || state == store.ControlInboxNacked {
		return true, nil
	}
	if state != store.ControlInboxReceived {
		return false, fmt.Errorf("%w: probe receipt inbox is %s", store.ErrIllegalPhase, state)
	}
	if h.sink == nil {
		return false, nil
	}
	if err := h.sink.HandleProbeMessage(s.nodeID, item.MessageType, []byte(item.SemanticPayload)); err != nil {
		if !isPermanentProbeReceiptError(err) {
			h.audit("PROBE_SINK_ERROR", fmt.Sprintf(`{"node_id":%q,"type":%q,"err":%q}`, s.nodeID, item.MessageType, err.Error()))
			return false, nil
		}
		if rejectErr := h.store.SetControlInboxStateExact(item, store.ControlInboxNacked); rejectErr != nil {
			h.audit("PROBE_RECEIPT_REJECTION_STATE_ERROR", fmt.Sprintf(`{"node_id":%q,"err":%q}`, s.nodeID, rejectErr.Error()))
			return false, nil
		}
		h.audit("PROBE_RECEIPT_REJECTED", fmt.Sprintf(`{"node_id":%q,"reason":%q}`, s.nodeID, err.Error()))
		return true, nil
	}
	if err := h.store.SetControlInboxStateExact(item, store.ControlInboxProcessed); err != nil {
		h.audit("PROBE_RECEIPT_STATE_ERROR", fmt.Sprintf(`{"node_id":%q,"err":%q}`, s.nodeID, err.Error()))
		return false, nil
	}
	return true, nil
}

// handleProbePlaneMessage records a durable probe-plane A2C message and
// forwards it to the configured ProbeSink (the P10 consumption interface).
// probe_armed is normally a correlated result of a controller probe_arm
// command and advances that outbox row; probe_ingress_receipt and
// probe_result are agent-initiated and have no outbox row. A sink failure is
// audited but never kills the session — the durable record is the source of
// truth and the probe manager can re-read it.
func (h *Hub) handleProbePlaneMessage(s *ControlSession, env protocol.Envelope) error {
	hdr := env.Header
	operationID := ""
	if hdr.MessageType == "probe_ingress_receipt" {
		// Receipt payloads are opaque to the transport, so derive the
		// deterministic operation binding from the exact durable payload. This
		// is also the retry key used for the semantic Controller acknowledgement.
		digest := sha256.Sum256(env.Payload)
		operationID = hex.EncodeToString(digest[:])
	}
	item := store.ControlInboxItem{
		MessageID:       hex.EncodeToString(hdr.MessageID[:]),
		NodeID:          s.nodeID,
		MessageType:     hdr.MessageType,
		OperationID:     operationID,
		SemanticPayload: string(env.Payload),
		State:           "RECEIVED",
	}
	if hdr.MessageType == "probe_ingress_receipt" {
		// processProbeReceipt owns the per-message lock across admission,
		// sink execution, and exact completion. The delivery lock is not
		// re-entrant.
		accepted, processErr := h.processProbeReceipt(s, item)
		if processErr != nil {
			return processErr
		}
		if !accepted {
			return nil
		}
		receiptID := security.MessageID(operationID, "message_receipt")
		payload := fmt.Sprintf(`{"operation_id":%q}`, operationID)
		writeCtx, cancel := context.WithTimeout(context.Background(), h.cfg.ControlWriteTimeout)
		defer cancel()
		return s.writeEnvelope(writeCtx, receiptID, "message_receipt", []byte(payload))
	}

	// Serialize the generic probe-plane sink path as well. Its exact inbox
	// completion may outlive the session owner that admitted the sink, and the
	// keyed lock prevents an overlapping replay from entering before completion.
	unlock := h.probeDeliveryLocks.acquire(item.MessageID)
	defer unlock()
	duplicate, err := h.store.RecordControlInboxOwned(s.owner, item)
	if err != nil {
		return err
	}
	if duplicate {
		// A duplicate is only a transport-level replay marker. If the first
		// delivery failed after RecordControlInbox committed, the row remains
		// RECEIVED and the same deterministic message must re-enter the sink.
		// Both terminal dispositions suppress forwarding. probe_armed still
		// needs its outbox correlation/receipt path after PROCESSED.
		state, stateErr := h.store.ControlInboxState(hex.EncodeToString(hdr.MessageID[:]))
		if stateErr != nil {
			h.audit("PROBE_INBOX_STATE_ERROR", fmt.Sprintf(`{"node_id":%q,"type":%q,"err":%q}`, s.nodeID, hdr.MessageType, stateErr.Error()))
			return nil
		}
		if state == store.ControlInboxNacked ||
			(state == store.ControlInboxProcessed && hdr.MessageType != "probe_armed") {
			return nil
		}
	}
	messageID := hex.EncodeToString(hdr.MessageID[:])
	state, err := h.store.ControlInboxState(messageID)
	if err != nil {
		h.audit("PROBE_INBOX_STATE_ERROR", fmt.Sprintf(`{"node_id":%q,"type":%q,"err":%q}`, s.nodeID, hdr.MessageType, err.Error()))
		return nil
	}
	if state == store.ControlInboxNacked {
		return nil
	}
	if state == store.ControlInboxReceived {
		if h.sink == nil {
			// The inbox is the durable handoff boundary. An optional P10 sink
			// may be absent in a transport-only hub; retain the authenticated
			// payload as RECEIVED without tearing down the session.
			return nil
		}
		if err := h.sink.HandleProbeMessage(s.nodeID, hdr.MessageType, env.Payload); err != nil {
			h.audit("PROBE_SINK_ERROR", fmt.Sprintf(`{"node_id":%q,"type":%q,"err":%q}`, s.nodeID, hdr.MessageType, err.Error()))
			// The exact RECEIVED inbox row is the retry token. A downstream
			// failure must not close the authenticated control session.
			return nil
		}
		if err := h.store.SetControlInboxStateExact(item, store.ControlInboxProcessed); err != nil {
			// The sink may have durably advanced the probe operation before
			// this inbox-state write. Keep the session alive and leave RECEIVED
			// for deterministic redelivery; exact row identity prevents a
			// stale handler from completing unrelated authenticated material.
			h.audit("PROBE_STATE_ERROR", fmt.Sprintf(`{"node_id":%q,"type":%q,"err":%q}`, s.nodeID, hdr.MessageType, err.Error()))
			return nil
		}
	}
	if hdr.MessageType == "probe_armed" {
		// Correlate only after the sink has durably accepted RDY1. A missing
		// row is tolerated for revalidation arms; internal lookup failures
		// remain retryable and must not be silently treated as absence.
		row, agentOp, err := h.matchOutboxRow(s, hdr.MessageID, hdr.MessageType)
		if err == nil {
			if err := h.advanceResultRow(s, row, agentOp); err != nil {
				return err
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			h.audit("PROBE_ARM_CORRELATION_ERROR", fmt.Sprintf(`{"node_id":%q,"err":%q}`, s.nodeID, err.Error()))
		}
	}
	return nil
}

// handleAgentResult durably records an A2C semantic result, correlates it to
// the controller outbox row, advances it to SEMANTIC_ACKED (claiming and
// marking sent if the result beat the pump on reconnect), and returns a C2A
// durable receipt so the agent can GC its outbox row.
func (h *Hub) handleAgentResult(s *ControlSession, env protocol.Envelope) error {
	hdr := env.Header
	messageID := hex.EncodeToString(hdr.MessageID[:])

	// Correlate before the first durable insert. An attacker/buggy peer must not
	// be able to seed a replay tombstone for an arbitrary message id and later
	// have it treated as a valid deletion/result completion.
	row, agentOp, err := h.matchOutboxRow(s, hdr.MessageID, hdr.MessageType)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			h.audit("CONTROL_RESULT_CORRELATION_ERROR", fmt.Sprintf(`{"node_id":%q,"type":%q,"err":%q}`, s.nodeID, hdr.MessageType, err.Error()))
			// A transient/internal lookup failure is retryable. Keep the session
			// alive and leave no inbox tombstone until correlation succeeds.
			return nil
		}
		// The outbox may have been garbage-collected after the controller
		// consumed the Agent's receipt while the Agent did not receive the C2A
		// receipt. The exact inbox row is the only migration-free replay token.
		// It must carry the operation binding established by the original indexed
		// correlation; node/type/payload equality alone is not an owner proof.
		existing, getErr := h.store.ControlInboxItemByMessageID(messageID)
		if getErr != nil {
			return err
		}
		if existing.NodeID != s.nodeID || existing.MessageType != hdr.MessageType ||
			existing.SemanticPayload != string(env.Payload) {
			return fmt.Errorf("%w: result replay message %q binding/material differs", store.ErrMessageConflict, messageID)
		}
		if existing.OperationID == "" {
			return fmt.Errorf("%w: result replay message %q has no durable operation binding", store.ErrMessageConflict, messageID)
		}
		switch existing.State {
		case store.ControlInboxNacked:
			// A permanently rejected result is a terminal transport disposition;
			// never recreate an outbox row or repeat its downstream effect.
			return nil
		case store.ControlInboxReceived, store.ControlInboxProcessed:
			// No outbox row remains to advance. Re-send only the deterministic
			// receipt; the Agent journal deduplicates it by message id. A RECEIVED
			// row remains the durable retry record for any operation-specific
			// recovery worker.
			receiptID := security.MessageID(existing.OperationID, "message_receipt")
			payload := fmt.Sprintf(`{"operation_id":%q}`, existing.OperationID)
			writeCtx, cancel := context.WithTimeout(context.Background(), h.cfg.ControlWriteTimeout)
			defer cancel()
			return s.writeEnvelope(writeCtx, receiptID, "message_receipt", []byte(payload))
		default:
			return fmt.Errorf("%w: result replay inbox is %s", store.ErrIllegalPhase, existing.State)
		}
	}
	item := store.ControlInboxItem{
		MessageID:       messageID,
		NodeID:          s.nodeID,
		MessageType:     hdr.MessageType,
		OperationID:     agentOp,
		SemanticPayload: string(env.Payload),
		State:           store.ControlInboxReceived,
	}
	_, err = h.store.RecordControlInboxOwned(s.owner, item)
	if err != nil {
		// Rows written by pre-correlation schema versions have no operation
		// discriminator. The outbox match above is the required proof before
		// filling that legacy NULL/empty field; never bind from payload alone.
		existing, getErr := h.store.ControlInboxItemByMessageID(messageID)
		if getErr != nil || existing.NodeID != item.NodeID || existing.MessageType != item.MessageType ||
			existing.SemanticPayload != item.SemanticPayload ||
			(existing.OperationID != "" && existing.OperationID != agentOp) {
			return err
		}
		if existing.OperationID == "" {
			if bindErr := h.store.BindControlInboxOperationIDOwned(s.owner, messageID, agentOp); bindErr != nil {
				return bindErr
			}
		}
	}

	state, err := h.store.ControlInboxState(messageID)
	if err != nil {
		h.audit("CONTROL_RESULT_INBOX_STATE_ERROR", fmt.Sprintf(`{"node_id":%q,"type":%q,"err":%q}`, s.nodeID, hdr.MessageType, err.Error()))
		return nil
	}
	if state == store.ControlInboxNacked {
		// A permanently rejected duplicate must not re-enter a sink or advance
		// the correlated outbox as if the result had succeeded.
		return nil
	}
	if state != store.ControlInboxReceived && state != store.ControlInboxProcessed {
		return fmt.Errorf("%w: result inbox is %s", store.ErrIllegalPhase, state)
	}

	// probe_arm has two semantic result forms on the existing operation_complete
	// wire: binary RDY1 on success and a JSON Agent journal NACK on application
	// failure. The latter is translated to the existing probe_result sink path;
	// it must never be handed to the RDY1 parser.
	if row.MessageType == "probe_arm" && state == store.ControlInboxReceived {
		if h.sink == nil {
			// Preserve the exact correlated result for a later replay when the
			// optional probe consumer is wired; a missing sink is not a frame
			// violation and must not close the authenticated session.
			return nil
		}
		sinkType := "probe_armed"
		sinkPayload := env.Payload
		if isProbeArmNACK(env.Payload) {
			sinkType = "probe_result"
			sinkPayload = []byte(fmt.Sprintf(`{"probe_id":%q,"outcome":"REJECTED"}`, row.OperationID))
		}
		if err := h.sink.HandleProbeMessage(s.nodeID, sinkType, sinkPayload); err != nil {
			h.audit("PROBE_SINK_ERROR", fmt.Sprintf(`{"node_id":%q,"type":%q,"err":%q}`, s.nodeID, sinkType, err.Error()))
			// Keep RECEIVED as the retry token. A transient application sink
			// failure must not kill an authenticated session or emit a semantic
			// receipt before downstream processing succeeded.
			return nil
		}
		if err := h.store.SetControlInboxStateOwned(s.owner, messageID, store.ControlInboxProcessed); err != nil {
			// The sink may have durably advanced the probe operation before this
			// inbox-state write. Leave RECEIVED for deterministic redelivery.
			h.audit("PROBE_ARMED_STATE_ERROR", fmt.Sprintf(`{"node_id":%q,"err":%q}`, s.nodeID, err.Error()))
			return nil
		}
	}
	if err := h.advanceResultRow(s, row, agentOp); err != nil {
		return err
	}
	return nil
}

// isProbeArmNACK recognizes the Agent journal's exact application-failure
// result. Invalid or non-JSON payloads remain on the binary RDY1 path and are
// rejected by the probe sink rather than being guessed as NACKs.
func isProbeArmNACK(payload []byte) bool {
	var result struct {
		Status    string `json:"status"`
		Reason    string `json:"reason"`
		Recovered bool   `json:"recovered"`
	}
	if err := protocol.DecodeStrictJSONInto(payload, &result); err != nil {
		return false
	}
	return result.Status == "nacked"
}

// advanceResultRow advances a correlated outbox row to SEMANTIC_ACKED with
// legal single steps and writes the C2A durable receipt so the agent can GC
// its outbox row. Shared by handleAgentResult and the probe_armed path.
func (h *Hub) advanceResultRow(s *ControlSession, row store.ControlOutboxItem, agentOp string) error {
	if err := h.ensureOutboxSemanticACKed(s, row); err != nil {
		return err
	}
	receiptID := security.MessageID(agentOp, "message_receipt")
	payload := fmt.Sprintf(`{"operation_id":%q}`, agentOp)
	writeCtx, cancel := context.WithTimeout(context.Background(), h.cfg.ControlWriteTimeout)
	defer cancel()
	return s.writeEnvelope(writeCtx, receiptID, "message_receipt", []byte(payload))
}

// ensureOutboxSemanticACKed converges one correlated row to SEMANTIC_ACKED
// without weakening the store FSM. The pump and inbound frame loop race on
// purpose, so a stale transition result is handled by re-reading the row and
// retrying the next legal step.
func (h *Hub) ensureOutboxSemanticACKed(s *ControlSession, row store.ControlOutboxItem) error {
	// Re-read the row before every single-step transition. The outbox pump and
	// the inbound frame loop are concurrent: a result can race a pump claim (or
	// a receipt can race the result handler). Acting on the snapshot returned by
	// matchOutboxRow would turn that benign race into an illegal-phase session
	// failure. Each failed transition is therefore retried from the newly
	// observed state; the FSM itself remains strict and single-step.
	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		current, err := h.store.ControlOutboxItemByOperation(row.OperationID, row.MessageType)
		if errors.Is(err, store.ErrNotFound) {
			// A concurrent A2C receipt already consumed the row. The result is
			// durably recorded, so re-sending the deterministic C2A receipt is
			// safe and lets the Agent deduplicate it if needed.
			lastErr = nil
			break
		}
		if err != nil {
			return err
		}
		switch current.State {
		case "PENDING":
			err = h.store.ClaimControlOutboxOperationOwned(current.OperationID, current.MessageType, s.owner)
		case "CLAIMED":
			err = h.store.MarkControlOutboxSentOwned(current.OperationID, current.MessageType, s.owner)
		case "SENT":
			err = h.store.AcceptControlSemanticACKOwned(current.OperationID, current.MessageType, s.owner)
		case "SEMANTIC_ACKED":
			// A result resend on a new session proves that this row is still
			// live; rebind it before the follow-up receipt.
			err = h.store.RebindControlOutboxSessionOwned(current.OperationID, current.MessageType, s.owner)
			if err == nil {
				lastErr = nil
				attempt = 8
				continue
			}
		default:
			return fmt.Errorf("%w: operation %q is %s", store.ErrIllegalPhase, current.OperationID, current.State)
		}
		if err == nil {
			lastErr = nil
			continue
		}
		lastErr = err
		if !errors.Is(err, store.ErrIllegalPhase) {
			return err
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return nil
}

// handleAgentReceipt advances the controller outbox row SEMANTIC_ACKED ->
// RECEIPTED -> GC. A replayed receipt for a row the controller already
// consumed (recorded in control_inbox, outbox row GC'd — the agent resends
// because its C2A receipt was lost) is a cached duplicate: tolerate the
// failed row match idempotently instead of killing the session (mirrors
// handleAgentResult).
func (h *Hub) handleAgentReceipt(s *ControlSession, env protocol.Envelope) error {
	hdr := env.Header
	agentOperationID, err := operationIDFromReceipt(env.Payload)
	if err != nil {
		return err
	}
	expectedReceiptID := security.MessageID(agentOperationID, "message_receipt")
	if hdr.MessageID != expectedReceiptID {
		return errors.New("receipt does not match deterministic message id")
	}

	// The authenticated receipt operation is an Agent-side transport identity.
	// Resolve the Controller operation only through the indexed durable result
	// correlations; a receipt payload must never select a deletion record.
	row, err := h.matchOutboxRowByReceiptOperationID(s, agentOperationID)
	messageID := hex.EncodeToString(hdr.MessageID[:])
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		// The outbox may already have been GC'd after a prior identical receipt.
		// Only an exact durable inbox row is a cached duplicate; storage errors or
		// material mismatches must remain visible to the authenticated session.
		existing, getErr := h.store.ControlInboxItemByMessageID(messageID)
		if getErr == nil {
			if existing.NodeID != s.nodeID || existing.MessageType != hdr.MessageType ||
				(existing.OperationID != "" && existing.OperationID != agentOperationID) ||
				existing.SemanticPayload != string(env.Payload) {
				return fmt.Errorf("%w: receipt replay message %q binding/material differs", store.ErrMessageConflict, messageID)
			}
			return nil
		}
		if !errors.Is(getErr, store.ErrNotFound) {
			return getErr
		}
		return err
	}

	item := store.ControlInboxItem{
		MessageID:       messageID,
		NodeID:          s.nodeID,
		MessageType:     hdr.MessageType,
		OperationID:     agentOperationID,
		SemanticPayload: string(env.Payload),
		State:           store.ControlInboxReceived,
	}
	if _, err := h.store.RecordControlInboxOwned(s.owner, item); err != nil {
		if !errors.Is(err, store.ErrMessageConflict) {
			return err
		}
		// Legacy rows may have been recorded before the operation binding was
		// added. The exact receipt correlation above is the proof used to fill it;
		// payload equality is checked before the binding is repaired.
		existing, getErr := h.store.ControlInboxItemByMessageID(messageID)
		if getErr != nil || existing.NodeID != item.NodeID || existing.MessageType != item.MessageType ||
			existing.SemanticPayload != item.SemanticPayload ||
			(existing.OperationID != "" && existing.OperationID != agentOperationID) {
			return err
		}
		if existing.OperationID == "" {
			if bindErr := h.store.BindControlInboxOperationIDOwned(s.owner, messageID, agentOperationID); bindErr != nil {
				return bindErr
			}
		}
	}
	state, err := h.store.ControlInboxState(messageID)
	if err != nil {
		return err
	}
	if state == store.ControlInboxNacked {
		// A permanently rejected receipt is a transport tombstone only. It
		// must never consume the correlated outbox row on replay.
		return nil
	}
	if state != store.ControlInboxReceived && state != store.ControlInboxProcessed {
		return fmt.Errorf("%w: receipt inbox is %s", store.ErrIllegalPhase, state)
	}
	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		if err := h.ensureOutboxSemanticACKed(s, row); err != nil {
			return err
		}
		lastErr = h.store.AcceptControlReceiptOwnedInbox(s.owner, store.ControlReceipt{
			ReceiptMessageID:  messageID,
			SemanticPayload:   string(env.Payload),
			InboxOperationID:  agentOperationID,
			OutboxOperationID: row.OperationID,
			OutboxMessageType: row.MessageType,
		})
		if lastErr == nil {
			return nil
		}
		if !errors.Is(lastErr, store.ErrIllegalPhase) {
			return lastErr
		}
		// Another receipt may have consumed the row between the convergence
		// read and this transaction. The exact inbox tombstone proves that this
		// frame is the same durable receipt, so treating the already-GC'd row as
		// success is idempotent and does not widen correlation.
		if _, rowErr := h.store.ControlOutboxItemByOperation(row.OperationID, row.MessageType); errors.Is(rowErr, store.ErrNotFound) {
			if existing, inboxErr := h.store.ControlInboxItemByMessageID(messageID); inboxErr == nil &&
				existing.NodeID == s.nodeID && existing.MessageType == hdr.MessageType &&
				existing.OperationID == agentOperationID && existing.SemanticPayload == string(env.Payload) {
				return nil
			}
		}
	}
	return lastErr
}

// outboxPump claims PENDING rows and sends them as C2A envelopes. A fresh
// session first requeues anything left in flight from a previous session
// (semantic resend, v0.8 §6.1).
func (h *Hub) outboxPump(ctx context.Context, s *ControlSession) {
	closeOnError := func(event string, err error) {
		h.audit(event, fmt.Sprintf(`{"node_id":%q,"err":%q}`, s.nodeID, err.Error()))
		// A pump error is a session-fatal delivery failure. Returning by itself
		// would leave the inbound loop and socket alive with no worker to drain
		// the outbox; close the session so the normal reconnect path can retry.
		s.close()
	}
	if _, err := h.store.RequeueControlOutboxForOwner(s.owner); err != nil {
		closeOnError("CONTROL_OUTBOX_REQUEUE_FAILED", err)
		return
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
			items, err := h.store.ClaimControlOutboxOwned(s.owner, outboxClaimLimit)
			if err != nil {
				closeOnError("CONTROL_OUTBOX_CLAIM_FAILED", err)
				return
			}
			for _, item := range items {
				// P14 repair-1 H2c/M3a/L4: delivery is re-gated AT DELIVERY TIME,
				// per tick, not from a handshake-captured bool. A cleanup-only
				// tombstone, a RESTORE_RECONCILIATION, or a per-node restore
				// quarantine must block forbidden orchestrating rows EVEN IF they
				// were enqueued (and left in flight) BEFORE the tombstone/quarantine
				// existed. The denied row is requeued (kept owned, never orphaned,
				// never stranded in CLAIMED) so a later reauthorization can retry it.
				allowed, delErr := h.store.DeliveryAllowed(item.NodeID, item.MessageType)
				if delErr != nil {
					closeOnError("CONTROL_OUTBOX_DELIVERY_GATE_FAILED", delErr)
					return
				}
				if !allowed {
					if err := h.store.RequeueControlOutboxItemOwned(item.OperationID, item.MessageType, s.owner); err != nil {
						closeOnError("CONTROL_OUTBOX_REQUEUE_ITEM_FAILED", err)
						return
					}
					continue
				}
				msgID := security.MessageID(item.OperationID, item.MessageType)
				if err := s.writeEnvelope(ctx, msgID, item.MessageType, []byte(item.SemanticPayload)); err != nil {
					closeOnError("CONTROL_OUTBOX_WRITE_FAILED", err)
					return
				}
				if err := h.store.MarkControlOutboxSentOwned(item.OperationID, item.MessageType, s.owner); err != nil {
					closeOnError("CONTROL_OUTBOX_MARK_SENT_FAILED", err)
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
func (h *Hub) register(s *ControlSession) bool {
	h.sessionsMu.Lock()
	if h.closed {
		h.sessionsMu.Unlock()
		s.close()
		return false
	}
	old := h.sessions[s.nodeID]
	h.sessions[s.nodeID] = s
	h.sessionsMu.Unlock()
	if old != nil {
		old.close()
	}
	if err := h.store.SetNodeControlStateOwned(s.owner, "ONLINE"); err != nil {
		h.audit("CONTROL_STATE_FAILED", fmt.Sprintf(`{"node_id":%q,"err":%q}`, s.nodeID, err.Error()))
	}
	return true
}

func (h *Hub) unregister(s *ControlSession) {
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	if h.sessions[s.nodeID] == s {
		delete(h.sessions, s.nodeID)
		if err := h.store.SetNodeControlStateOwned(s.owner, "OFFLINE"); err != nil {
			h.audit("CONTROL_STATE_FAILED", fmt.Sprintf(`{"node_id":%q,"err":%q}`, s.nodeID, err.Error()))
		}
	}
}

// ForceCloseNodeSession terminates the active control session for a node if one
// is established (repair-1 M3a). The force-delete lifecycle calls this after the
// durable cleanup tombstone is written so a pre-tombstone session cannot keep
// pumping orchestrating rows. A reconnect after this point completes a fresh
// handshake that re-reads IsCleanupOnly, and the outbox pump re-gates delivery
// per tick regardless.
func (h *Hub) ForceCloseNodeSession(nodeID string) {
	h.sessionsMu.Lock()
	s := h.sessions[nodeID]
	h.sessionsMu.Unlock()
	if s != nil {
		s.close()
	}
}

// ControllerInstanceID returns the raw 16-byte controller instance id.
func (h *Hub) ControllerInstanceID() [16]byte { return h.instanceID() }

// ControllerPublicKey returns the controller signing public key (P10 wires
// this into deployment profiles as the agent's pin source).
func (h *Hub) ControllerPublicKey() ed25519.PublicKey {
	return h.keyring.PublicKey()
}

// AgentPublicKey returns the verified agent public key of the ACTIVE session
// for a node, if one is connected. The store persists only the key HASH
// (frozen enrollment contract); the full key exists only on the live session,
// which is exactly when probe-plane frames (RDY1/RCT1) need verification.
// P10's probe manager consumes the channel through this accessor.
func (h *Hub) AgentPublicKey(nodeID string) (ed25519.PublicKey, bool) {
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()
	s, ok := h.sessions[nodeID]
	if !ok || s == nil {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), s.agentPub...), true
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

// matchOutboxRow correlates an agent result envelope to an indexed in-flight
// outbox row and returns the row plus the agent-side operation id used.
// PENDING rows are included so a result that beats the reconnect pump can
// still be correlated (the handler advances the FSM legally). A miss is
// fail-closed; scanning a bounded prefix can never be a correctness fallback.
func (h *Hub) matchOutboxRow(s *ControlSession, resultMsgID [16]byte, resultType string) (store.ControlOutboxItem, string, error) {
	states := []string{"PENDING", "CLAIMED", "SENT", "SEMANTIC_ACKED"}
	resultHex := hex.EncodeToString(resultMsgID[:])
	if resultType == "operation_complete" {
		row, err := h.store.ControlOutboxItemByCorrelation(s.nodeID, resultHex, "operation_complete", states...)
		if err == nil {
			cmdMsgID := security.MessageID(row.OperationID, row.MessageType)
			return row, hex.EncodeToString(cmdMsgID[:]), nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return store.ControlOutboxItem{}, "", fmt.Errorf("agent result correlation: %w", err)
		}
		row, err = h.store.ControlOutboxItemByCorrelation(s.nodeID, resultHex, "controller_operation_complete", states...)
		if err == nil {
			return row, row.OperationID, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return store.ControlOutboxItem{}, "", fmt.Errorf("agent result alternate correlation: %w", err)
		}
	} else {
		row, err := h.store.ControlOutboxItemByCorrelation(s.nodeID, resultHex, "command", states...)
		if err == nil {
			return row, row.OperationID, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return store.ControlOutboxItem{}, "", fmt.Errorf("agent result correlation: %w", err)
		}
	}
	return store.ControlOutboxItem{}, "", fmt.Errorf("agent result does not match any in-flight outbox row: %w", store.ErrNotFound)
}

// matchOutboxRowByCommandMessageID correlates an A2C receipt (referencing the
// command message id) to an in-flight row. PENDING rows are included for the
// reconnect race (result/receipt beating the pump).
func (h *Hub) matchOutboxRowByCommandMessageID(s *ControlSession, commandMsgIDHex string) (store.ControlOutboxItem, string, error) {
	row, err := h.store.ControlOutboxItemByCorrelation(s.nodeID, strings.ToLower(commandMsgIDHex), "command", "PENDING", "CLAIMED", "SENT", "SEMANTIC_ACKED")
	if err == nil {
		return row, row.OperationID, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.ControlOutboxItem{}, "", fmt.Errorf("receipt correlation: %w", err)
	}
	return store.ControlOutboxItem{}, "", fmt.Errorf("receipt does not match any in-flight outbox row: %w", store.ErrNotFound)
}

// matchOutboxRowByReceiptOperationID resolves a receipt's Agent-side operation
// identity through the exact deterministic result correlations persisted on the
// Controller outbox. The returned row carries the independent Controller
// semantic operation identity used by receipt GC.
func (h *Hub) matchOutboxRowByReceiptOperationID(s *ControlSession, agentOperationID string) (store.ControlOutboxItem, error) {
	resultID := security.MessageID(agentOperationID, "operation_complete")
	resultHex := hex.EncodeToString(resultID[:])
	states := []string{"PENDING", "CLAIMED", "SENT", "SEMANTIC_ACKED"}
	row, err := h.store.ControlOutboxItemByCorrelation(s.nodeID, resultHex, "operation_complete", states...)
	if err == nil {
		return row, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.ControlOutboxItem{}, fmt.Errorf("receipt result correlation: %w", err)
	}
	row, err = h.store.ControlOutboxItemByCorrelation(s.nodeID, resultHex, "controller_operation_complete", states...)
	if err == nil {
		return row, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.ControlOutboxItem{}, fmt.Errorf("receipt controller-result correlation: %w", err)
	}
	return store.ControlOutboxItem{}, fmt.Errorf("receipt does not match any in-flight outbox row: %w", store.ErrNotFound)
}

// operationIDFromReceipt parses {"operation_id": "..."} from the receipt
// payload.
func operationIDFromReceipt(payload []byte) (string, error) {
	var v struct {
		OperationID string `json:"operation_id"`
	}
	if err := protocol.DecodeStrictJSONInto(payload, &v); err != nil {
		return "", errors.New("malformed receipt payload")
	}
	if v.OperationID == "" {
		return "", errors.New("receipt payload missing operation_id")
	}
	return v.OperationID, nil
}
