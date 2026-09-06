package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/controller"
	"github.com/gxbrave/AntiNAT/internal/controller/probe"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
	"github.com/gxbrave/AntiNAT/internal/traversal"
)

const periodicReceiptGlobalLiteral = "8.8.8.8"

type periodicReceiptRouteTable struct{}

func (periodicReceiptRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	return netip.MustParseAddr("127.0.0.1"), "lo", true, nil
}

func (periodicReceiptRouteTable) IPv4Addresses() ([]traversal.IPv4Address, error) {
	return []traversal.IPv4Address{{
		Interface: "lo",
		Addr:      netip.MustParseAddr(periodicReceiptGlobalLiteral),
	}}, nil
}

// requirePeriodicReceiptAlias exercises the actual kernel bind and source-bound
// dial path. The route table alone is deliberately not enough to make this test
// pass. A pre-existing alias is reused and is never removed by this test.
func requirePeriodicReceiptAlias(t *testing.T) {
	t.Helper()
	alias := periodicReceiptGlobalLiteral + "/32"
	out, err := exec.Command("ip", "addr", "add", alias, "dev", "lo").CombinedOutput()
	owned := err == nil
	if err != nil && !strings.Contains(string(out), "Address already assigned") {
		t.Skipf("direct-v4 capability unavailable: cannot add %s to lo: %v (%s)", alias, err, strings.TrimSpace(string(out)))
	}
	cleanupAlias := func() {
		if owned {
			_ = exec.Command("ip", "addr", "del", alias, "dev", "lo").Run()
		}
	}

	ip := net.ParseIP(periodicReceiptGlobalLiteral).To4()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: ip, Port: 0})
	if err != nil {
		cleanupAlias()
		t.Skipf("direct-v4 capability unavailable: cannot bind %s: %v", periodicReceiptGlobalLiteral, err)
	}
	defer listener.Close()
	acceptDone := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
		close(acceptDone)
	}()
	dialer := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: ip}}
	conn, err := dialer.Dial("tcp4", listener.Addr().String())
	if err != nil {
		cleanupAlias()
		t.Skipf("direct-v4 capability unavailable: source-bound dial from %s failed: %v", periodicReceiptGlobalLiteral, err)
	}
	_ = conn.Close()
	select {
	case <-acceptDone:
	case <-time.After(2 * time.Second):
		cleanupAlias()
		t.Skipf("direct-v4 capability unavailable: source-bound dial to %s was not usable", periodicReceiptGlobalLiteral)
	}
	if owned {
		t.Cleanup(cleanupAlias)
	}
}

type periodicReceiptBodyGate struct {
	readStarted chan struct{}
	release     chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

func newPeriodicReceiptBodyGate() *periodicReceiptBodyGate {
	return &periodicReceiptBodyGate{
		readStarted: make(chan struct{}),
		release:     make(chan struct{}),
	}
}

func (g *periodicReceiptBodyGate) signalRead() {
	g.once.Do(func() { close(g.readStarted) })
}

func (g *periodicReceiptBodyGate) Release() {
	g.releaseOnce.Do(func() { close(g.release) })
}

func (g *periodicReceiptBodyGate) WaitRead(timeout time.Duration) bool {
	select {
	case <-g.readStarted:
		return true
	case <-time.After(timeout):
		return false
	}
}

type periodicReceiptReadCloser struct {
	io.ReadCloser
	gate *periodicReceiptBodyGate
	once sync.Once
}

func (r *periodicReceiptReadCloser) Read(p []byte) (int, error) {
	r.once.Do(r.gate.signalRead)
	<-r.gate.release
	return r.ReadCloser.Read(p)
}

type periodicReceiptRoundTripper struct {
	base http.RoundTripper
	gate *periodicReceiptBodyGate
}

func (t periodicReceiptRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &periodicReceiptReadCloser{ReadCloser: resp.Body, gate: t.gate}
	return resp, nil
}

func waitPeriodicReceipt(t *testing.T, timeout time.Duration, description string, fn func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ok, err := fn()
		if err != nil {
			lastErr = err
		} else if ok {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("timed out waiting for %s: %v", description, lastErr)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func periodicReceiptAuditCount(s *store.Store, after int64, eventType string) (int, error) {
	events, err := s.AdminEventsAfter(after, 4096)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, event := range events {
		if event.EventType == eventType {
			count++
		}
	}
	return count, nil
}

func periodicReceiptProbeRecord(st *localstate.Store, operationID string) (localstate.ArmedProbe, bool, error) {
	probeBytes, err := hex.DecodeString(operationID)
	if err != nil || len(probeBytes) != 16 {
		return localstate.ArmedProbe{}, false, fmt.Errorf("decode probe id: %w", err)
	}
	var probeID [16]byte
	copy(probeID[:], probeBytes)
	return st.LoadArmedProbe(probeID)
}

func periodicReceiptEnvelopeID(receipt []byte) (semanticID, envelopeID string) {
	digest := sha256.Sum256(receipt)
	semanticID = hex.EncodeToString(digest[:])
	messageID := security.MessageID(semanticID, "probe_ingress_receipt")
	return semanticID, hex.EncodeToString(messageID[:])
}

func periodicReceiptKinds(results []store.ProbeResult) map[string]bool {
	kinds := make(map[string]bool, len(results))
	for _, result := range results {
		kinds[result.Kind] = true
	}
	return kinds
}

func TestPeriodicReceiptRetrySameSessionAfterChallengeNotEstablished(t *testing.T) {
	requirePeriodicReceiptAlias(t)

	bodyGate := newPeriodicReceiptBodyGate()
	providerHTTPClient := &http.Client{
		Transport: periodicReceiptRoundTripper{base: http.DefaultTransport, gate: bodyGate},
		Timeout:   40 * time.Second,
	}
	ctrl, err := controller.New(controller.Config{
		ListenAddress:      "127.0.0.1:0",
		StorePath:          filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:             t.TempDir(),
		Clock:              time.Now,
		ProviderHTTPClient: providerHTTPClient,
		MaxProbeRounds:     4,
	})
	if err != nil {
		t.Fatalf("controller New: %v", err)
	}

	providerPublic, providerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("provider key: %v", err)
	}
	provider, err := probe.NewProvider(probe.ProviderConfig{
		ControllerPublicKey: ctrl.Hub().ControllerPublicKey(),
		ProviderPrivateKey:  providerPrivate,
		DialTimeout:         5 * time.Second,
		ExchangeTimeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("provider New: %v", err)
	}
	providerCtx, providerCancel := context.WithCancel(context.Background())
	if err := provider.Start(providerCtx); err != nil {
		providerCancel()
		t.Fatalf("provider Start: %v", err)
	}
	providerServer := httptest.NewServer(provider.Handler())

	nodeID := "node-periodic"
	forwardID := "forward-periodic"
	if err := ctrl.Store().CreateNode(store.Node{ID: nodeID, Name: "periodic-node"}); err != nil {
		providerServer.Close()
		_ = provider.Close()
		providerCancel()
		t.Fatalf("create node: %v", err)
	}
	token, err := ctrl.Store().CreateEnrollmentToken(nodeID, 3600)
	if err != nil {
		providerServer.Close()
		_ = provider.Close()
		providerCancel()
		t.Fatalf("enrollment token: %v", err)
	}
	if _, err := ctrl.Store().CreateProbeProvider(store.ProbeProvider{
		ID:                 "provider-periodic",
		Name:               "periodic-provider",
		PublicKey:          hex.EncodeToString(providerPublic),
		EgressIP:           periodicReceiptGlobalLiteral,
		Endpoint:           providerServer.URL,
		Enabled:            true,
		IndependentVantage: true,
	}); err != nil {
		providerServer.Close()
		_ = provider.Close()
		providerCancel()
		t.Fatalf("register provider: %v", err)
	}
	if err := ctrl.Start(); err != nil {
		providerServer.Close()
		_ = provider.Close()
		providerCancel()
		t.Fatalf("controller Start: %v", err)
	}

	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listener: %v", err)
	}
	go func() {
		for {
			conn, acceptErr := target.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				// The probe gate consumes the provider connection. Ordinary data-plane
				// sessions still terminate at this real target listener.
				_ = conn.Close()
			}()
		}
	}()

	agentCtx, agentCancel := context.WithCancel(context.Background())
	app, err := New(Config{
		StateDir:            t.TempDir(),
		Endpoint:            "http://" + ctrl.Addr(),
		NodeID:              nodeID,
		Token:               token,
		ControllerPublicKey: ctrl.Hub().ControllerPublicKey(),
		Heartbeat:           50 * time.Millisecond,
		RouteTable:          periodicReceiptRouteTable{},
		LivenessInterval:    50 * time.Millisecond,
	})
	if err != nil {
		target.Close()
		agentCancel()
		_ = ctrl.Shutdown(context.Background())
		providerServer.Close()
		_ = provider.Close()
		providerCancel()
		t.Fatalf("agent New: %v", err)
	}
	t.Cleanup(func() {
		bodyGate.Release()
		agentCancel()
		_ = app.Shutdown(context.Background())
		_ = target.Close()
		providerServer.Close()
		_ = provider.Close()
		providerCancel()
		_ = ctrl.Shutdown(context.Background())
	})
	if err := app.Start(agentCtx); err != nil {
		t.Fatalf("agent Start: %v", err)
	}
	if !app.Ready() || !ctrl.Ready() {
		t.Fatalf("apps not ready after startup: controller=%v agent=%v", ctrl.Ready(), app.Ready())
	}

	waitPeriodicReceipt(t, 10*time.Second, "controller node ONLINE", func() (bool, error) {
		node, err := ctrl.Store().GetNode(nodeID)
		return err == nil && node.ControlState == "ONLINE", err
	})
	nodeBefore, err := ctrl.Store().GetNode(nodeID)
	if err != nil {
		t.Fatalf("read initial node session: %v", err)
	}
	agentEpochBefore, agentSessionBefore, err := app.Store().CurrentSession()
	if err != nil {
		t.Fatalf("read initial agent session: %v", err)
	}
	if nodeBefore.CurrentConnectionEpoch != agentEpochBefore || nodeBefore.CurrentSessionID != agentSessionBefore || agentSessionBefore == "" {
		t.Fatalf("controller/agent session mismatch before arm: controller=(%d,%q), agent=(%d,%q)", nodeBefore.CurrentConnectionEpoch, nodeBefore.CurrentSessionID, agentEpochBefore, agentSessionBefore)
	}

	spec := protocol.ForwardSpec{
		ForwardID:       forwardID,
		Name:            "integration",
		Protocol:        protocol.ProtocolTCP,
		Target:          target.Addr().String(),
		Strategy:        protocol.StrategyDirectV4,
		DesiredRevision: 1,
		Presence:        protocol.PresencePresent,
	}
	desired := protocol.DesiredState{NodeID: nodeID, Forwards: []protocol.ForwardSpec{spec}}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal forward spec: %v", err)
	}
	desiredJSON, err := json.Marshal(desired)
	if err != nil {
		t.Fatalf("marshal desired state: %v", err)
	}
	activation := protocol.ActivationID(forwardID, 1)
	forward := store.Forward{
		ID:                  forwardID,
		NodeID:              nodeID,
		Name:                "integration",
		Protocol:            string(protocol.ProtocolTCP),
		CurrentActivationID: hex.EncodeToString(activation[:]),
		Revision:            1,
	}
	_, replayed, err := ctrl.Store().CreateForwardBundle(
		context.Background(),
		forward,
		store.ForwardSpec{ID: "spec-" + forwardID, ForwardID: forwardID, Revision: 1, SpecJSON: string(specJSON)},
		store.ControlOutboxItem{OperationID: "desired-" + forwardID, MessageType: "desired", NodeID: nodeID, SemanticPayload: string(desiredJSON), State: "PENDING"},
		store.IdempotencyRecord{Key: "idempotency-" + forwardID, Route: "/api/v1/forwards", Principal: "integration-test", RequestHash: "request-" + forwardID, ResponseStatus: http.StatusCreated, ResponseBody: string(desiredJSON)},
	)
	if err != nil {
		t.Fatalf("CreateForwardBundle: %v", err)
	}
	if replayed {
		t.Fatal("CreateForwardBundle unexpectedly replayed")
	}

	waitPeriodicReceipt(t, 15*time.Second, "real desired state applied", func() (bool, error) {
		state, found, err := app.Store().GetAppliedState(forwardID)
		if err != nil || !found {
			return false, err
		}
		return state.SpecRevision == 1 && state.ActualBindHost == periodicReceiptGlobalLiteral && state.ActualBindPort != 0, nil
	})
	applied, found, err := app.Store().GetAppliedState(forwardID)
	if err != nil || !found {
		t.Fatalf("load applied forward: found=%v err=%v", found, err)
	}
	endpoint := net.JoinHostPort(applied.ActualBindHost, fmt.Sprintf("%d", applied.ActualBindPort))
	if err := protocol.ValidateProbeEndpoint(endpoint); err != nil {
		t.Fatalf("applied probe endpoint %q: %v", endpoint, err)
	}

	snapshot, found, err := app.Store().LoadActivationSnapshot(forwardID)
	if err != nil || !found {
		t.Fatalf("load exact activation snapshot: found=%v err=%v", found, err)
	}
	if snapshot.Activation != hex.EncodeToString(activation[:]) || snapshot.Generation != 1 {
		t.Fatalf("activation snapshot identity = activation %q generation %d, want %q/1", snapshot.Activation, snapshot.Generation, hex.EncodeToString(activation[:]))
	}
	snapshotStatesJSON, err := json.Marshal(snapshot.States)
	if err != nil {
		t.Fatalf("marshal exact activation states: %v", err)
	}
	currentForward, err := ctrl.Store().GetForward(forwardID)
	if err != nil {
		t.Fatalf("read current forward revision: %v", err)
	}
	if err := ctrl.Store().SetForwardRuntimeStatus(forwardID, snapshot.Activation, currentForward.Revision, string(snapshotStatesJSON)); err != nil {
		t.Fatalf("seed controller runtime mirror from exact agent snapshot: %v", err)
	}

	auditCursor, err := ctrl.Store().LastAdminEventID()
	if err != nil {
		t.Fatalf("read audit cursor: %v", err)
	}
	op, err := ctrl.ArmProbe(context.Background(), nodeID, forwardID, endpoint)
	if err != nil {
		t.Fatalf("controller ArmProbe: %v", err)
	}
	if op.Status != "PENDING" || op.ChallengeHash != "" {
		t.Fatalf("new probe operation = %+v", op)
	}
	if !bodyGate.WaitRead(15 * time.Second) {
		t.Fatal("provider response body was not gated after the WAN1/ACK1 exchange")
	}

	var preGateRecord localstate.ArmedProbe
	var preGateSemanticID, preGateEnvelopeID string
	waitPeriodicReceipt(t, 10*time.Second, "consumed and sent unacknowledged receipt", func() (bool, error) {
		record, found, err := periodicReceiptProbeRecord(app.Store(), op.ID)
		if err != nil || !found {
			return false, err
		}
		if !record.Consumed || !record.ReceiptSent || record.ReceiptAcknowledged || len(record.Receipt) == 0 {
			return false, nil
		}
		preGateRecord = record
		preGateSemanticID, preGateEnvelopeID = periodicReceiptEnvelopeID(record.Receipt)
		return true, nil
	})
	var preInbox store.ControlInboxItem
	waitPeriodicReceipt(t, 10*time.Second, "pre-gate probe receipt inbox", func() (bool, error) {
		item, err := ctrl.Store().ControlInboxItemByMessageID(preGateEnvelopeID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return false, nil
			}
			return false, err
		}
		preInbox = item
		return true, nil
	})
	if preInbox.State != "RECEIVED" || preInbox.OperationID != preGateSemanticID || preInbox.SemanticPayload != string(preGateRecord.Receipt) {
		t.Fatalf("pre-gate inbox = %+v, want RECEIVED exact receipt and semantic operation id", preInbox)
	}
	preOp, err := ctrl.Store().GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("read pre-gate operation: %v", err)
	}
	if preOp.ChallengeHash != "" {
		t.Fatalf("pre-gate challenge hash = %q, want empty while response body is held", preOp.ChallengeHash)
	}

	waitPeriodicReceipt(t, 5*time.Second, "repeated retryable probe sink errors", func() (bool, error) {
		count, err := periodicReceiptAuditCount(ctrl.Store(), auditCursor, "PROBE_SINK_ERROR")
		return count >= 2, err
	})
	preNode, err := ctrl.Store().GetNode(nodeID)
	if err != nil {
		t.Fatalf("read pre-gate node: %v", err)
	}
	preAgentEpoch, preAgentSession, err := app.Store().CurrentSession()
	if err != nil {
		t.Fatalf("read pre-gate agent session: %v", err)
	}
	if preNode.ControlState != "ONLINE" || preNode.CurrentConnectionEpoch != nodeBefore.CurrentConnectionEpoch || preNode.CurrentSessionID != nodeBefore.CurrentSessionID {
		events, _ := ctrl.Store().AdminEventsAfter(auditCursor, 4096)
		t.Fatalf("controller session changed or went offline before release: before=%+v after=%+v events=%+v", nodeBefore, preNode, events)
	}
	if preAgentEpoch != agentEpochBefore || preAgentSession != agentSessionBefore || !app.Ready() {
		events, _ := ctrl.Store().AdminEventsAfter(auditCursor, 4096)
		t.Fatalf("agent session/readiness changed before release: before=(epoch:%d session:%q) after=(epoch:%d session:%q ready:%v) events=%+v", agentEpochBefore, agentSessionBefore, preAgentEpoch, preAgentSession, app.Ready(), events)
	}
	if preOp.Status != "IN_FLIGHT" {
		t.Fatalf("pre-gate operation status = %q, want IN_FLIGHT", preOp.Status)
	}

	bodyGate.Release()
	waitPeriodicReceipt(t, 15*time.Second, "OPEN_FROM_VANTAGE probe join", func() (bool, error) {
		current, err := ctrl.Store().GetProbeOperation(op.ID)
		if err != nil {
			return false, err
		}
		if current.Status == string(protocol.OutcomeOpenFromVantage) {
			return true, nil
		}
		results, resultsErr := ctrl.Store().ListProbeResults(op.ID)
		if resultsErr != nil {
			return false, fmt.Errorf("status=%q results-error=%v", current.Status, resultsErr)
		}
		events, _ := ctrl.Store().AdminEventsAfter(auditCursor, 4096)
		return false, fmt.Errorf("status=%q challenge=%q results=%+v events=%+v", current.Status, current.ChallengeHash, results, events)
	})
	processedDeadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(processedDeadline) {
		record, found, recordErr := periodicReceiptProbeRecord(app.Store(), op.ID)
		inbox, inboxErr := ctrl.Store().ControlInboxItemByMessageID(preGateEnvelopeID)
		if recordErr == nil && found && inboxErr == nil && record.ReceiptAcknowledged && inbox.State == "PROCESSED" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	finalReceiptRecord, receiptFound, receiptErr := periodicReceiptProbeRecord(app.Store(), op.ID)
	finalReceiptInbox, inboxErr := ctrl.Store().ControlInboxItemByMessageID(preGateEnvelopeID)
	if receiptErr != nil || inboxErr != nil || !receiptFound || !finalReceiptRecord.ReceiptAcknowledged || finalReceiptInbox.State != "PROCESSED" {
		finalOp, opErr := ctrl.Store().GetProbeOperation(op.ID)
		finalNode, nodeErr := ctrl.Store().GetNode(nodeID)
		events, _ := ctrl.Store().AdminEventsAfter(auditCursor, 4096)
		t.Fatalf("receipt acknowledgement did not converge: record=%+v found=%v err=%v inbox=%+v err=%v op=%+v err=%v node=%+v err=%v events=%+v ready=(controller:%v agent:%v)", finalReceiptRecord, receiptFound, receiptErr, finalReceiptInbox, inboxErr, finalOp, opErr, finalNode, nodeErr, events, ctrl.Ready(), app.Ready())
	}
	results, err := ctrl.Store().ListProbeResults(op.ID)
	if err != nil {
		t.Fatalf("list joined probe evidence: %v", err)
	}
	kinds := periodicReceiptKinds(results)
	for _, kind := range []string{"provider", "wan1", "ack1", "rct1"} {
		if !kinds[kind] {
			t.Fatalf("joined probe evidence missing %q: %+v", kind, results)
		}
	}
	waitPeriodicReceipt(t, 10*time.Second, "durable probe outcome acknowledgement", func() (bool, error) {
		return ctrl.Store().ProbeOutcomeAcknowledged(op.ID)
	})

	finalSnapshot := app.ActivationSnapshot(forwardID)
	if finalSnapshot == nil || finalSnapshot.WanReachabilityState != string(protocol.OutcomeOpenFromVantage) || finalSnapshot.PublicationState != "PUBLISHED_VERIFIED" {
		t.Fatalf("agent final activation snapshot = %+v", finalSnapshot)
	}
	finalNode, err := ctrl.Store().GetNode(nodeID)
	if err != nil {
		t.Fatalf("read final node: %v", err)
	}
	finalAgentEpoch, finalAgentSession, err := app.Store().CurrentSession()
	if err != nil {
		t.Fatalf("read final agent session: %v", err)
	}
	if !ctrl.Ready() || !app.Ready() || finalNode.ControlState != "ONLINE" {
		t.Fatalf("readiness/control lost after join: controller=%v agent=%v node=%+v", ctrl.Ready(), app.Ready(), finalNode)
	}
	if finalNode.CurrentConnectionEpoch != nodeBefore.CurrentConnectionEpoch || finalNode.CurrentSessionID != nodeBefore.CurrentSessionID || finalAgentEpoch != agentEpochBefore || finalAgentSession != agentSessionBefore {
		t.Fatalf("session changed during receipt retry/join: controller before=(%d,%q) after=(%d,%q), agent before=(%d,%q) after=(%d,%q)", nodeBefore.CurrentConnectionEpoch, nodeBefore.CurrentSessionID, finalNode.CurrentConnectionEpoch, finalNode.CurrentSessionID, agentEpochBefore, agentSessionBefore, finalAgentEpoch, finalAgentSession)
	}
}
