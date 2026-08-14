package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
)

// testEnv wires a store, a keyring, a node keypair, and an in-process fake
// provider service speaking the controller<->provider protocol.
type testEnv struct {
	t        *testing.T
	store    *store.Store
	keyring  *security.Keyring
	manager  *Manager
	provider *fakeProvider
	nodePriv ed25519.PrivateKey
	nodePub  ed25519.PublicKey
}

// fakeProvider implements the provider side of the signed request/result
// protocol in-process.
type fakeProvider struct {
	priv     ed25519.PrivateKey
	ctrlPub  ed25519.PublicKey
	mu       sync.Mutex
	lastReq  *providerRequest
	rejected bool
}

func (p *fakeProvider) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/probe/v1/request", func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeProviderRequest(r.Body, p.ctrlPub)
		if err != nil {
			writeProviderResult(w, p.priv, providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "bad_request"})
			return
		}
		p.mu.Lock()
		p.lastReq = req
		rejected := p.rejected
		p.mu.Unlock()

		var challenge [32]byte
		rand.Read(challenge[:])
		var digest32 [32]byte
		copy(digest32[:], mustHex(req.ArmDigest))
		var probeID, providerID, activation, opaque [16]byte
		copy(probeID[:], mustHex(req.ProbeID))
		copy(providerID[:], mustHex(req.ProviderID))
		copy(activation[:], mustHex(req.Activation))
		copy(opaque[:], mustHex(req.ExpiryOpaque))
		frame := protocol.ProviderFrame{
			ArmDigest:    digest32,
			ProbeID:      probeID,
			ProviderID:   providerID,
			Activation:   activation,
			Endpoint:     req.Endpoint,
			ExpiryOpaque: opaque,
			Challenge:    challenge,
		}
		frame.Signature = ed25519.Sign(p.priv, frame.SigningBytes())

		conn, err := net.DialTimeout("tcp4", req.Endpoint, 2*time.Second)
		if err != nil {
			writeProviderResult(w, p.priv, providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "unreachable"})
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(wan1Wire(frame)); err != nil {
			writeProviderResult(w, p.priv, providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "send_failed"})
			return
		}
		ackBuf := make([]byte, 4+32+32+64)
		if _, err := readFullConn(conn, ackBuf); err != nil || rejected {
			writeProviderResult(w, p.priv, providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "no_ack"})
			return
		}
		nodePub := mustHex(req.NodePublicKey)
		if _, err := protocol.ParseProbeACK(ackBuf, ed25519.PublicKey(nodePub)); err != nil {
			writeProviderResult(w, p.priv, providerResult{ProbeID: req.ProbeID, Accepted: false, Reason: "bad_ack"})
			return
		}
		chash := frame.ChallengeHash()
		writeProviderResult(w, p.priv, providerResult{
			ProbeID:       req.ProbeID,
			Accepted:      true,
			ChallengeHash: hex.EncodeToString(chash[:]),
			WAN1Frame:     hex.EncodeToString(wan1Wire(frame)),
			ACK1Frame:     hex.EncodeToString(ackBuf),
			Reason:        "ack_verified",
		})
	})
	return mux
}

func wan1Wire(f protocol.ProviderFrame) []byte {
	return append(f.Canonical(), f.Signature...)
}


func newTestEnv(t *testing.T, providerRejected bool) *testEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	kr, err := security.LoadOrCreateKeyring(t.TempDir(), 1)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	nodePub, nodePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provPub, provPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prov := &fakeProvider{priv: provPriv, ctrlPub: kr.PublicKey(), rejected: providerRejected}
	srv := httptest.NewServer(prov.handler())
	t.Cleanup(srv.Close)

	mgr, err := NewManager(ManagerConfig{
		Store:   st,
		Keyring: kr,
		Clock:   time.Now,
		HTTPClient: srv.Client(),
		NodePublicKey: func(nodeID string) (ed25519.PublicKey, bool) {
			return nodePub, true
		},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	if _, err := st.CreateProbeProvider(store.ProbeProvider{
		ID: "prov-1", Name: "edge", PublicKey: hex.EncodeToString(provPub),
		EgressIP: "198.51.100.9", Endpoint: srv.URL, Enabled: true,
	}); err != nil {
		t.Fatalf("register provider: %v", err)
	}
	return &testEnv{t: t, store: st, keyring: kr, manager: mgr, provider: prov, nodePriv: nodePriv, nodePub: nodePub}
}

func (e *testEnv) createNodeForward(t *testing.T) {
	t.Helper()
	if err := e.store.CreateNode(store.Node{ID: "n1", Name: "n1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.CreateForward(store.Forward{ID: "f1", NodeID: "n1", Name: "fwd", Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
}

func (e *testEnv) armAndGetPayload(t *testing.T, endpoint string) (store.ProbeOperation, protocol.ProbeArm) {
	t.Helper()
	op, err := e.manager.Arm(context.Background(), "n1", "f1", "act-1", endpoint)
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	item, err := e.store.ControlOutboxItemByOperation(op.ID, "probe_arm")
	if err != nil {
		t.Fatalf("outbox arm payload: %v", err)
	}
	arm, err := protocol.ParseProbeArm([]byte(item.SemanticPayload))
	if err != nil {
		t.Fatalf("outbox payload is not ARM1: %v", err)
	}
	return op, arm
}

// TestArmEnqueuesProbeArm covers Story 1: Arm persists the probe operation
// and enqueues a probe_arm C2A command whose payload is exactly the
// canonical ARM1 frame WITHOUT any challenge material.
func TestArmEnqueuesProbeArm(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if op.Status != "PENDING" || op.Endpoint != "198.51.100.7:8080" {
		t.Fatalf("unexpected op: %+v", op)
	}
	if hex.EncodeToString(arm.ProbeID[:]) != op.ID {
		t.Fatalf("outbox probe id mismatch")
	}
	item, _ := env.store.ControlOutboxItemByOperation(op.ID, "probe_arm")
	if strings.Contains(item.SemanticPayload, "challenge") {
		t.Fatal("challenge material leaked into the control outbox")
	}
}

// TestProviderNotRequestedBeforeArmed covers Story 1 RED: the provider must
// not be called before the durable probe_armed result arrives.
func TestProviderNotRequestedBeforeArmed(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	env.armAndGetPayload(t, "198.51.100.7:8080")
	env.provider.mu.Lock()
	req := env.provider.lastReq
	env.provider.mu.Unlock()
	if req != nil {
		t.Fatal("provider was requested before probe_armed")
	}
}

// TestProbeArmedTriggersProviderRequest covers arm->armed->provider: after a
// valid RDY1 the manager marks the op ARMED and requests the provider.
func TestProbeArmedTriggersProviderRequest(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")

	rdy := signRDY1(t, env.nodePriv, arm)
	if err := env.manager.HandleProbeMessage("n1", "probe_armed", rdy); err != nil {
		t.Fatalf("handle probe_armed: %v", err)
	}
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "ARMED" {
		t.Fatalf("status = %q, want ARMED", got.Status)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		env.provider.mu.Lock()
		req := env.provider.lastReq
		env.provider.mu.Unlock()
		if req != nil {
			if req.ProbeID != op.ID {
				t.Fatalf("provider got wrong probe id")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("provider was never requested after probe_armed")
}

// globalTestEndpoint binds a documentation-range (TEST-NET) global literal on
// loopback so the probe endpoint is contract-valid (protocol.IsGlobalEndpoint
// treats documentation ranges as global; the frozen golden vectors use
// 198.51.100.7) and the provider can really dial it. Skips when the address
// cannot be assigned (non-root CI).
func globalTestEndpoint(t *testing.T) (net.Listener, string) {
	t.Helper()
	if out, err := exec.Command("ip", "addr", "add", "198.51.100.7/32", "dev", "lo").CombinedOutput(); err != nil {
		// Already assigned or not permitted: still try to bind.
		_ = out
	}
	t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", "198.51.100.7/32", "dev", "lo").Run() })
	ln, err := net.Listen("tcp4", "198.51.100.7:0")
	if err != nil {
		t.Skipf("cannot bind TEST-NET global endpoint (need lo alias): %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().String()
}

// TestJoinOpensFromVantage covers Story 2 GREEN: provider result (WAN1+ACK1)
// plus the agent's RCT1 receipt join to OPEN_FROM_VANTAGE.
func TestJoinOpensFromVantage(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)

	// A real listener the provider can dial (the agent's published endpoint).
	ln, endpoint := globalTestEndpoint(t)
	op, arm := env.armAndGetPayload(t, endpoint)

	// The agent accepts the provider connection, verifies WAN1, answers ACK1
	// and sends RCT1 (signed by the node key).
	agentDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			agentDone <- err
			return
		}
		defer conn.Close()
		raw, err := readWAN1(conn)
		if err != nil {
			agentDone <- err
			return
		}
		frame, err := protocol.ParseProviderFrame(raw)
		if err != nil {
			agentDone <- err
			return
		}
		// ACK1 on the same connection.
		chash := frame.ChallengeHash()
		digest := arm.Digest()
		ackBody := append([]byte(protocol.ProbeMagicACK), digest[:]...)
		ackBody = append(ackBody, chash[:]...)
		ackSig := ed25519.Sign(env.nodePriv, ackBody)
		ackWire := append(ackBody, ackSig...)
		if _, err := conn.Write(ackWire); err != nil {
			agentDone <- err
			return
		}
		// RCT1 over the control channel (delivered via the sink).
		rct1 := signRCT1(t, env.nodePriv, arm, chash)
		if err := env.manager.HandleProbeMessage("n1", "probe_ingress_receipt", rct1); err != nil {
			agentDone <- err
			return
		}
		agentDone <- nil
	}()

	if err := env.manager.HandleProbeMessage("n1", "probe_armed", signRDY1(t, env.nodePriv, arm)); err != nil {
		t.Fatal(err)
	}
	if err := <-agentDone; err != nil {
		t.Fatalf("agent ingress: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, err := env.store.GetProbeOperation(op.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status == string(protocol.OutcomeOpenFromVantage) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("operation never reached OPEN_FROM_VANTAGE")
}

// TestJoinRejectsControlOnlyReceipt covers Story 2 RED: a forged control-only
// receipt without a provider result can never open.
func TestJoinRejectsControlOnlyReceipt(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")

	forged := signRCT1(t, env.nodePriv, arm, [32]byte{0xaa})
	if err := env.manager.HandleProbeMessage("n1", "probe_ingress_receipt", forged); err != nil {
		t.Fatalf("handle forged receipt: %v", err)
	}
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status == string(protocol.OutcomeOpenFromVantage) {
		t.Fatal("forged receipt opened the operation")
	}
}

// TestProviderRejectedNeverOpens covers Story 2 RED: when the provider
// reports no ACK, the operation never opens even with a receipt.
func TestProviderRejectedNeverOpens(t *testing.T) {
	env := newTestEnv(t, true)
	env.createNodeForward(t)

	ln, endpoint := globalTestEndpoint(t)
	op, arm := env.armAndGetPayload(t, endpoint)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		raw, err := readWAN1(conn)
		if err != nil {
			return
		}
		frame, err := protocol.ParseProviderFrame(raw)
		if err != nil {
			return
		}
		chash := frame.ChallengeHash()
		rct1 := signRCT1(t, env.nodePriv, arm, chash)
		_ = env.manager.HandleProbeMessage("n1", "probe_ingress_receipt", rct1)
	}()

	if err := env.manager.HandleProbeMessage("n1", "probe_armed", signRDY1(t, env.nodePriv, arm)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status == string(protocol.OutcomeOpenFromVantage) {
		t.Fatal("operation opened without a verified provider ACK")
	}
}

// ---------------------------------------------------------------------------
// frame builders (shared with the E2E harness)
// ---------------------------------------------------------------------------

// signRDY1 signs an RDY1 frame for the arm with the node private key.
func signRDY1(t *testing.T, nodePriv ed25519.PrivateKey, arm protocol.ProbeArm) []byte {
	t.Helper()
	digest := arm.Digest()
	body := append([]byte(protocol.ProbeMagicArmed), digest[:]...)
	return append(body, ed25519.Sign(nodePriv, body)...)
}

func signRCT1(t *testing.T, nodePriv ed25519.PrivateKey, arm protocol.ProbeArm, challengeHash [32]byte) []byte {
	t.Helper()
	digest := arm.Digest()
	body := append([]byte(protocol.ProbeMagicReceipt), digest[:]...)
	body = append(body, challengeHash[:]...)
	body = append(body, arm.ProviderID[:]...)
	return append(body, ed25519.Sign(nodePriv, body)...)
}

// mustHex decodes a hex string (test helper).
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func readWAN1(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	const fixed = 4 + 32 + 16 + 16 + 16 + 1
	head := make([]byte, fixed)
	if _, err := readFullConn(conn, head); err != nil {
		return nil, err
	}
	endpointLen := int(head[fixed-1])
	rest := make([]byte, endpointLen+16+32+64)
	if _, err := readFullConn(conn, rest); err != nil {
		return nil, err
	}
	return append(head, rest...), nil
}
