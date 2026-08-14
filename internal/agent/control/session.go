package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// Control channel bounds (mirror the hub).
const (
	// maxEnvelopeBytes bounds one WS message (frame + header + payload + sig).
	maxEnvelopeBytes = 13 + protocol.MaxHeaderBytes + protocol.MaxPayloadBytes + 64
	// sessionIdleTimeout closes a session receiving no frames.
	sessionIdleTimeout = 3 * time.Minute
	// outboxPumpInterval is the outbox claim/send cadence.
	outboxPumpInterval = 50 * time.Millisecond
)

// ClientOptions configures the Agent control session client.
type ClientOptions struct {
	// Endpoint is the controller base URL (http:// or https://).
	Endpoint string
	// NodeID is the agent's node identity (store-form string).
	NodeID string
	// Store is the agent localstate store (journal + pins).
	Store *localstate.Store
	// Key is the agent node identity key.
	Key *security.NodeKey
	// Heartbeat is the A2C heartbeat interval (0 disables automatic
	// heartbeats; tests use a short interval).
	Heartbeat time.Duration
	// OnCommand handles an inbound command (desired/forward_delete/...)
	// between the journal's APPLYING and APPLIED/NACKED phases. It returns
	// the durable semantic result or an error that NACKs the operation.
	OnCommand func(ctx context.Context, op Operation) ([]byte, error)
	// Dialer overrides the WebSocket dialer (tests, family fallback).
	Dialer DialFunc
}

// DialFunc dials a WebSocket to the control path on endpoint.
type DialFunc func(ctx context.Context, endpoint string) (*websocket.Conn, error)

// Operation is one inbound command delivered to OnCommand.
type Operation struct {
	OperationID string
	MessageID   string
	MessageType string
	Payload     []byte
}

// Client is one Agent control session loop.
type Client struct {
	opts ClientOptions

	conn *websocket.Conn
	mu   sync.Mutex
	// outSeq is the agent's outbound sequence (A2C).
	outSeq uint64
	// inSeq is the last accepted inbound sequence (C2A).
	inSeq uint64
	// epoch/session are the ACTIVE session (persisted before activation).
	epoch   uint64
	session string

	closed chan struct{}
	once   sync.Once
}

// NewClient validates the options and builds a client.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Endpoint == "" {
		return nil, errors.New("control: client requires endpoint")
	}
	if opts.NodeID == "" {
		return nil, errors.New("control: client requires node id")
	}
	if opts.Store == nil {
		return nil, errors.New("control: client requires store")
	}
	if opts.Key == nil {
		return nil, errors.New("control: client requires node key")
	}
	if opts.Dialer == nil {
		opts.Dialer = defaultDialer
	}
	return &Client{opts: opts, closed: make(chan struct{})}, nil
}

// defaultDialer upgrades the controller endpoint to ws(s) and dials with the
// family-aware transport (A-only / AAAA-only / dual fallback, Story 6).
func defaultDialer(ctx context.Context, endpoint string) (*websocket.Conn, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("control: parse endpoint: %w", err)
	}
	scheme := "ws"
	if u.Scheme == "https" {
		scheme = "wss"
	}
	wsURL := scheme + "://" + u.Host + "/agent/v1/control"
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// The family policy applies to the TCP dial; the address here is
			// host:port from the WS URL.
			conn, _, err := DialEndpoint(ctx, "http://"+addr, net.DefaultResolver, 30*time.Second)
			return conn, err
		},
	}
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second},
	})
	if err != nil {
		return nil, fmt.Errorf("control: ws dial %s: %w", wsURL, err)
	}
	return conn, nil
}

// Close terminates the session.
func (c *Client) Close() {
	c.once.Do(func() {
		close(c.closed)
		if c.conn != nil {
			c.conn.CloseNow()
		}
	})
}

// SendMessage pushes an agent-initiated A2C message (P10 probe plane: the
// RCT1 probe_ingress_receipt). P08 declares that P10 consumes the control
// channel via interfaces; this is that outbound interface, the mirror of the
// controller-side ProbeSink. The message id is fresh per call and the frame
// is signed like any A2C envelope; callers must not use it for command
// results (those go through the durable outbox journal).
func (c *Client) SendMessage(ctx context.Context, messageType string, payload []byte) error {
	if c.opts.Store == nil {
		return errors.New("control: send message requires a store")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	return c.writeEnvelope(ctx, id, messageType, payload)
}

// Connect establishes ONE session: dial, mutual-challenge handshake, epoch
// persistence BEFORE socket activation, then starts the inbound frame loop,
// the outbox pump, and heartbeats. It returns once the handshake completes.
func (c *Client) Connect(ctx context.Context) error {
	// Load the pinned controller key (the trust anchor from enrollment).
	pins, err := c.opts.Store.ListControllerPins()
	if err != nil {
		return fmt.Errorf("control: load pins: %w", err)
	}
	if len(pins) != 1 {
		return fmt.Errorf("control: expected exactly one pinned controller, found %d (enroll first)", len(pins))
	}
	pin := pins[0]

	conn, err := c.opts.Dialer(ctx, c.opts.Endpoint)
	if err != nil {
		return err
	}
	conn.SetReadLimit(maxEnvelopeBytes)
	c.conn = conn

	if err := c.handshake(ctx, conn, pin); err != nil {
		conn.CloseNow()
		return err
	}

	// Requeue any un-receipted outbox rows for the new session (semantic
	// resend) and start the pumps.
	if _, err := c.opts.Store.RequeueOutboxForSession(c.epoch, c.session); err != nil {
		conn.CloseNow()
		return fmt.Errorf("control: requeue outbox: %w", err)
	}
	go c.frameLoop(ctx)
	go c.outboxPump(ctx)
	if c.opts.Heartbeat > 0 {
		go c.heartbeatLoop(ctx)
	}
	return nil
}

// handshake runs hello -> welcome -> final. The agent verifies the welcome
// against the PINNED controller key and persists the granted epoch/session
// BEFORE sending the final (v0.8 §6.3: persist before socket activation).
func (c *Client) handshake(ctx context.Context, conn *websocket.Conn, pin localstate.ControllerPin) error {
	curEpoch, curSession, err := c.opts.Store.CurrentSession()
	if err != nil {
		return fmt.Errorf("control: current session: %w", err)
	}
	instance := [16]byte{}
	if b, err := hex.DecodeString(pin.InstanceID); err == nil && len(b) == 16 {
		copy(instance[:], b)
	}
	var node [16]byte
	copy(node[:], c.opts.NodeID)
	var nonce [security.SessionNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	hello := security.SessionHello{
		ControllerInstanceID: instance,
		NodeID:               node,
		AgentCredentialVer:   c.opts.Key.CredentialVersion(),
		AgentPublicKey:       [32]byte(c.opts.Key.PublicKey()),
		AgentNonce:           nonce,
		AgentMaxEpoch:        curEpoch,
		ProtocolVersions:     "1",
	}
	sig, err := hello.Sign(c.opts.Key.PrivateKey())
	if err != nil {
		return err
	}
	if err := conn.Write(ctx, websocket.MessageBinary, append(hello.Canonical(), sig...)); err != nil {
		return fmt.Errorf("control: write hello: %w", err)
	}

	_, rawWelcome, err := conn.Read(ctx)
	if err != nil {
		return fmt.Errorf("control: read welcome: %w", err)
	}
	welcome, err := security.ParseSessionWelcome(rawWelcome, pin.PublicKey())
	if err != nil {
		return fmt.Errorf("control: verify welcome: %w (wrong pinned controller?)", err)
	}
	if welcome.ControllerInstanceID != instance {
		return errors.New("control: welcome from a different controller instance")
	}
	if welcome.ControllerKeyID != pin.KeyID {
		return errors.New("control: welcome key id does not match the pinned key")
	}
	if welcome.ConnectionEpoch < curEpoch {
		return fmt.Errorf("control: welcome epoch %d below accepted %d (downgrade)", welcome.ConnectionEpoch, curEpoch)
	}
	if curSession != "" && welcome.ConnectionEpoch == curEpoch && welcome.SessionID != curSession {
		return errors.New("control: same-epoch welcome with a different session (split brain)")
	}

	// PERSIST before activation (v0.8 §6.3).
	if err := c.opts.Store.AdvanceSession(welcome.ConnectionEpoch, welcome.SessionID); err != nil {
		return fmt.Errorf("control: persist epoch: %w", err)
	}
	c.epoch = welcome.ConnectionEpoch
	c.session = welcome.SessionID

	final := security.SessionFinal{
		ControllerInstanceID: welcome.ControllerInstanceID,
		NodeID:               node,
		ServerNonce:          welcome.ServerNonce,
		ConnectionEpoch:      welcome.ConnectionEpoch,
		SessionID:            welcome.SessionID,
	}
	fsig, err := final.Sign(c.opts.Key.PrivateKey())
	if err != nil {
		return err
	}
	if err := conn.Write(ctx, websocket.MessageBinary, append(final.Canonical(), fsig...)); err != nil {
		return fmt.Errorf("control: write final: %w", err)
	}
	return nil
}

// frameLoop reads C2A envelopes until the session dies. Any verification
// failure closes the session (fail closed).
func (c *Client) frameLoop(ctx context.Context) {
	for {
		readCtx, cancel := context.WithTimeout(ctx, sessionIdleTimeout)
		_, frame, err := c.conn.Read(readCtx)
		cancel()
		if err != nil {
			c.Close()
			return
		}
		if err := c.handleInboundFrame(readCtx, frame); err != nil {
			c.Close()
			return
		}
	}
}

// handleInboundFrame verifies and dispatches one C2A envelope.
func (c *Client) handleInboundFrame(ctx context.Context, frame []byte) error {
	pins, err := c.opts.Store.ListControllerPins()
	if err != nil || len(pins) != 1 {
		return errors.New("control: pinned controller lost")
	}
	env, stage, err := protocol.ParseEnvelope(frame, pins[0].PublicKey())
	if err != nil {
		return fmt.Errorf("control: envelope rejected at %s: %w", stage, err)
	}
	hdr := env.Header
	if hdr.Direction != protocol.DirectionC2A {
		return errors.New("control: wrong direction: expected C2A")
	}
	if hdr.ConnectionEpoch != c.epoch || hdr.SessionID != c.session {
		return errors.New("control: stale epoch/session in frame")
	}
	c.mu.Lock()
	expectedSeq := c.inSeq + 1
	if hdr.Sequence != expectedSeq {
		c.mu.Unlock()
		return fmt.Errorf("control: sequence %d, want %d", hdr.Sequence, expectedSeq)
	}
	c.inSeq = hdr.Sequence
	c.mu.Unlock()

	switch hdr.MessageType {
	case "desired", "forward_delete", "node_decommission", "probe_arm":
		return c.handleCommand(ctx, env)
	case "message_receipt":
		return c.handleReceipt(ctx, env)
	case "heartbeat", "status":
		return nil
	default:
		return fmt.Errorf("control: unexpected message type %q", hdr.MessageType)
	}
}

// handleCommand journals the command through the inbox FSM and delivers it to
// OnCommand (the P10 reconcile extension point). The semantic result is
// queued to the outbox; a handler error NACKs the operation and queues the
// nack payload so the controller still learns the outcome.
func (c *Client) handleCommand(ctx context.Context, env protocol.Envelope) error {
	hdr := env.Header
	msgID := hex.EncodeToString(hdr.MessageID[:])
	sum := sha256.Sum256(env.Payload)
	payloadHash := hex.EncodeToString(sum[:])

	dup, err := c.opts.Store.ReceiveCommand(c.epoch, c.session, msgID, msgID, hdr.MessageType, payloadHash, hdr.MessageType)
	if err != nil {
		return err
	}
	if dup {
		return nil // cached duplicate: result already queued (resend path)
	}
	if err := c.opts.Store.PersistOperationIntent(c.epoch, c.session, msgID); err != nil {
		return err
	}
	if err := c.opts.Store.MarkOperationApplying(c.epoch, c.session, msgID); err != nil {
		return err
	}

	var result []byte
	var applyErr error
	if c.opts.OnCommand != nil {
		result, applyErr = c.opts.OnCommand(ctx, Operation{
			OperationID: msgID,
			MessageID:   msgID,
			MessageType: hdr.MessageType,
			Payload:     env.Payload,
		})
	}
	if applyErr != nil {
		if err := c.opts.Store.NackOperation(c.epoch, c.session, msgID, applyErr.Error()); err != nil {
			return err
		}
		nackPayload, _ := json.Marshal(map[string]any{"status": "nacked", "reason": applyErr.Error()})
		return c.opts.Store.QueueResult(c.epoch, c.session, msgID, nackPayload)
	}
	if result == nil {
		result = []byte(`{"status":"applied"}`)
	}
	return c.opts.Store.CompleteOperation(c.epoch, c.session, msgID, result)
}

// handleReceipt applies the controller's durable receipt for one of the
// agent's outbox results: the receipt both semantically acks and durably
// receipts the row (the controller persists the result before sending it).
// On reconnect the receipt can beat the agent's own pump, so a PENDING row is
// advanced legally before the ack.
func (c *Client) handleReceipt(ctx context.Context, env protocol.Envelope) error {
	var v struct {
		OperationID string `json:"operation_id"`
	}
	if err := json.Unmarshal(env.Payload, &v); err != nil || v.OperationID == "" {
		return errors.New("control: malformed receipt payload")
	}
	op := v.OperationID
	state, present, err := c.opts.Store.OutboxState(op)
	if err != nil {
		return err
	}
	if !present {
		return nil // already GC'd (idempotent redelivery)
	}
	switch state {
	case "PENDING":
		if err := c.opts.Store.ClaimOutbox(c.epoch, c.session, op); err != nil {
			if errors.Is(err, localstate.ErrIllegalPhase) {
				return nil
			}
			return err
		}
		if err := c.opts.Store.MarkOutboxSent(c.epoch, c.session, op); err != nil {
			return err
		}
	case "CLAIMED":
		if err := c.opts.Store.MarkOutboxSent(c.epoch, c.session, op); err != nil {
			return err
		}
	case "SENT", "SEMANTIC_ACKED":
		// already sent; ack below is idempotent for SEMANTIC_ACKED
	default:
		return nil
	}
	if err := c.opts.Store.AcceptSemanticACK(c.epoch, c.session, op); err != nil {
		if errors.Is(err, localstate.ErrIllegalPhase) {
			return nil // already receipted/GC'd (idempotent redelivery)
		}
		return err
	}
	if err := c.opts.Store.AcceptReceipt(c.epoch, c.session, op); err != nil {
		if errors.Is(err, localstate.ErrAlreadyReceipted) {
			return nil
		}
		return err
	}
	return nil
}

// writeEnvelope signs and writes one A2C envelope with the next sequence.
func (c *Client) writeEnvelope(ctx context.Context, messageID [16]byte, messageType string, payload []byte) error {
	c.mu.Lock()
	c.outSeq++
	seq := c.outSeq
	c.mu.Unlock()

	pins, _ := c.opts.Store.ListControllerPins()
	var instance [16]byte
	keyID := ""
	if len(pins) == 1 {
		if b, err := hex.DecodeString(pins[0].InstanceID); err == nil && len(b) == 16 {
			copy(instance[:], b)
		}
		keyID = pins[0].KeyID
	}
	var node [16]byte
	copy(node[:], c.opts.NodeID)
	header := protocol.ProtectedHeader{
		ProtocolDomain:       protocol.ProtocolDomain,
		ControllerInstanceID: instance,
		NodeID:               node,
		ControllerKeyID:      keyID,
		AgentCredentialVer:   c.opts.Key.CredentialVersion(),
		ConnectionEpoch:      c.epoch,
		SessionID:            c.session,
		Direction:            protocol.DirectionA2C,
		Sequence:             seq,
		MessageID:            messageID,
		MessageType:          messageType,
		SchemaVersion:        1,
	}
	frame, err := protocol.BuildEnvelope(c.opts.Key.PrivateKey(), header, payload)
	if err != nil {
		return fmt.Errorf("control: build envelope: %w", err)
	}
	return c.conn.Write(ctx, websocket.MessageBinary, frame)
}

// outboxPump claims queued results and sends them as A2C operation_complete
// envelopes; each result is followed by a message_receipt for the command it
// answers so the controller can GC its outbox row.
func (c *Client) outboxPump(ctx context.Context) {
	ticker := time.NewTicker(outboxPumpInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		case <-ticker.C:
			if err := c.pumpOnce(ctx); err != nil {
				c.Close()
				return
			}
		}
	}
}

func (c *Client) pumpOnce(ctx context.Context) error {
	ids, err := c.opts.Store.OutboxOperationIDs()
	if err != nil {
		return err
	}
	for _, op := range ids {
		state, present, err := c.opts.Store.OutboxState(op)
		if err != nil || !present {
			continue
		}
		if state != "PENDING" {
			continue
		}
		result, err := c.opts.Store.ResultForOperation(c.epoch, c.session, op)
		if err != nil {
			continue // receipted concurrently
		}
		if err := c.opts.Store.ClaimOutbox(c.epoch, c.session, op); err != nil {
			if errors.Is(err, localstate.ErrIllegalPhase) {
				continue // racing receipt already advanced/GC'd the row
			}
			return err
		}
		// Result envelope: deterministic message id (resend dedup).
		msgID := security.MessageID(op, "operation_complete")
		if err := c.writeEnvelope(ctx, msgID, "operation_complete", result); err != nil {
			return err
		}
		// A racing receipt may have advanced the row (SEMANTIC_ACKED/GC);
		// tolerate the loss — the receipt proves the result is durable.
		if err := c.opts.Store.MarkOutboxSent(c.epoch, c.session, op); err != nil {
			if errors.Is(err, localstate.ErrIllegalPhase) {
				continue
			}
			return err
		}
		// Durable receipt for the answered command so the controller can GC
		// its outbox row (the controller correlates via the receipt's
		// operation_id = the command message id hex).
		receiptID := security.MessageID(op, "message_receipt")
		payload := []byte(fmt.Sprintf(`{"operation_id":%q}`, op))
		if err := c.writeEnvelope(ctx, receiptID, "message_receipt", payload); err != nil {
			return err
		}
	}
	return nil
}

// heartbeatLoop sends A2C heartbeat envelopes.
func (c *Client) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(c.opts.Heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		case <-ticker.C:
			var msgID [16]byte
			rand.Read(msgID[:])
			if err := c.writeEnvelope(ctx, msgID, "heartbeat", []byte(`{}`)); err != nil {
				c.Close()
				return
			}
		}
	}
}
