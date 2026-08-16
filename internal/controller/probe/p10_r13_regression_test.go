package probe

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// R13 RED: WAN verification mutates only WAN reachability, return path, and
// publication. Every independent controller mirror axis must survive the join
// byte-for-byte instead of being fabricated from WAN1/ACK1/RCT1 evidence.
func TestR13VerifiedJoinPreservesIndependentActivationAxes(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	before := protocol.ActivationStates{
		ControlState: "OFFLINE", ListenerState: "ERROR", MappingState: "PUBLIC_CANDIDATE",
		KeepaliveState: "NOT_REQUIRED", WanReachabilityState: "PROBING",
		ReturnPathState: "NOT_TESTED", TargetHealthState: "FAIL",
		PublicationState: "UNPUBLISHED", DataPlaneState: "DEGRADED",
	}
	rawBefore, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.store.SetForwardRuntimeStatus("f1", "act-1", string(rawBefore)); err != nil {
		t.Fatal(err)
	}

	ln, endpoint := globalTestEndpoint(t)
	op, arm := env.armAndGetPayload(t, endpoint)
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
		challenge := frame.ChallengeHash()
		digest := arm.Digest()
		ackBody := append([]byte(protocol.ProbeMagicACK), digest[:]...)
		ackBody = append(ackBody, challenge[:]...)
		if _, err := conn.Write(append(ackBody, ed25519.Sign(env.nodePriv, ackBody)...)); err != nil {
			agentDone <- err
			return
		}
		agentDone <- env.manager.HandleProbeMessage("n1", "probe_ingress_receipt", signRCT1(t, env.nodePriv, arm, challenge))
	}()
	if err := env.manager.HandleProbeMessage("n1", "probe_armed", signRDY1(t, env.nodePriv, arm)); err != nil {
		t.Fatal(err)
	}
	if err := <-agentDone; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		operation, err := env.store.GetProbeOperation(op.ID)
		if err != nil {
			t.Fatal(err)
		}
		if operation.Status != string(protocol.OutcomeOpenFromVantage) {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		row, err := env.store.GetForwardRuntimeStatus("f1")
		if err != nil {
			t.Fatal(err)
		}
		var after protocol.ActivationStates
		if err := json.Unmarshal([]byte(row.SnapshotJSON), &after); err != nil {
			t.Fatal(err)
		}
		if after.ControlState != before.ControlState || after.ListenerState != before.ListenerState ||
			after.MappingState != before.MappingState || after.KeepaliveState != before.KeepaliveState ||
			after.TargetHealthState != before.TargetHealthState || after.DataPlaneState != before.DataPlaneState {
			t.Fatalf("WAN join rewrote independent axes:\nbefore=%+v\nafter=%+v", before, after)
		}
		if after.WanReachabilityState != string(protocol.OutcomeOpenFromVantage) ||
			after.ReturnPathState != "VERIFIED" || after.PublicationState != "PUBLISHED_VERIFIED" {
			t.Fatalf("WAN-owned axes after join = %+v", after)
		}
		return
	}
	t.Fatal("operation never reached OPEN_FROM_VANTAGE")
}

// R13 RED: authenticated status payloads still reject duplicate, unknown,
// trailing, depth, and non-canonical integer forms before runtime CAS.
func TestR13ActivationStatusUsesStrictSemanticJSON(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	snapshot := `{"control_state":"ONLINE","listener_state":"READY","mapping_state":"PUBLIC_CANDIDATE","keepalive_state":"NOT_REQUIRED","wan_reachability_state":"NOT_TESTED","return_path_state":"NOT_TESTED","target_health_state":"UNKNOWN","publication_state":"NONE","data_plane_state":"READY"}`
	payloads := []string{
		`{"forward_id":"f1","forward_id":"f1","activation":"act-1","generation":1,"snapshot":` + snapshot + `}`,
		`{"forward_id":"f1","activation":"act-1","generation":1,"snapshot":` + snapshot + `,"unknown":true}`,
		`{"forward_id":"f1","activation":"act-1","generation":1,"snapshot":` + snapshot + `} {}`,
		`{"forward_id":"f1","activation":"act-1","generation":1e0,"snapshot":` + snapshot + `}`,
	}
	for _, payload := range payloads {
		if err := env.manager.HandleActivationStatus("n1", []byte(payload)); err == nil {
			t.Fatalf("ambiguous activation status accepted: %s", payload)
		}
	}
	if _, err := env.store.GetForwardRuntimeStatus("f1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ambiguous statuses created runtime state: %v", err)
	}
}

func setR13ProviderLimit(t *testing.T, cfg *ProviderConfig, name string, value int) {
	t.Helper()
	field := reflect.ValueOf(cfg).Elem().FieldByName(name)
	if !field.IsValid() {
		t.Fatalf("ProviderConfig.%s is missing", name)
	}
	field.SetInt(int64(value))
}

func r13SignedProviderBody(t *testing.T, controllerPriv ed25519.PrivateKey, controller string, nodeByte byte, endpoint string, sequence int, now int64) []byte {
	t.Helper()
	nodePub := bytes.Repeat([]byte{nodeByte}, ed25519.PublicKeySize)
	req := providerRequest{
		Schema: providerRequestSchema, ControllerInstance: controller, ControllerKeyID: "key-r13",
		NodePublicKey: hex.EncodeToString(nodePub), NodePublicKeyHash: hex.EncodeToString(hash256(nodePub)),
		ProbeID: fmtHex16R13(sequence), ProviderID: strings.Repeat("22", 16), Activation: strings.Repeat("33", 16),
		Endpoint: endpoint, ExpectedSourceIP: "c6336409", ExpiryOpaque: strings.Repeat("44", 16),
		TTLMS: 30000, ArmDigest: strings.Repeat(string("abcdef"[sequence%6]), 64), TimestampUnix: now,
	}
	canonical, err := req.canonical()
	if err != nil {
		t.Fatal(err)
	}
	req.Signature = hex.EncodeToString(ed25519.Sign(controllerPriv, canonical))
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func fmtHex16R13(v int) string {
	return strings.Repeat("0", 28) + hex.EncodeToString([]byte{byte(v >> 8), byte(v)})
}

func r13ProviderReason(t *testing.T, client *http.Client, url string, body []byte) string {
	t.Helper()
	resp, err := client.Post(url+"/probe/v1/request", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result providerResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result.Reason
}

// R13 RED: provider admission has independent controller/node/endpoint minute
// buckets and a daily budget. Each subtest varies the other identities so a
// single global counter cannot accidentally satisfy the requirement.
func TestR13ProviderAdmissionBudgetsEveryIdentityAxis(t *testing.T) {
	for _, tc := range []struct {
		name       string
		field      string
		controller func(int) string
		node       func(int) byte
		endpoint   func(int) string
	}{
		{"controller", "ControllerMinuteLimit", func(int) string { return "controller-r13" }, func(i int) byte { return byte(i + 1) }, func(i int) string { return "198.51.100.7:" + string(rune('1'+i)) }},
		{"node", "NodeMinuteLimit", func(i int) string { return "controller-" + string(rune('a'+i)) }, func(int) byte { return 7 }, func(i int) string { return "198.51.100.7:" + string(rune('1'+i)) }},
		{"endpoint", "EndpointMinuteLimit", func(i int) string { return "controller-" + string(rune('a'+i)) }, func(i int) byte { return byte(i + 1) }, func(int) string { return "198.51.100.7:9" }},
		{"daily", "DailyBudget", func(i int) string { return "controller-" + string(rune('a'+i)) }, func(i int) byte { return byte(i + 1) }, func(i int) string { return "198.51.100.7:" + string(rune('1'+i)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controllerPub, controllerPriv, _ := ed25519.GenerateKey(rand.Reader)
			_, providerPriv, _ := ed25519.GenerateKey(rand.Reader)
			now := time.Unix(50_000, 0)
			cfg := ProviderConfig{
				ControllerPublicKey: controllerPub, ProviderPrivateKey: providerPriv,
				Clock: func() time.Time { return now }, MaxRequests: 1000,
				DialTimeout: time.Millisecond, ExchangeTimeout: time.Millisecond,
			}
			for _, field := range []string{"ControllerMinuteLimit", "NodeMinuteLimit", "EndpointMinuteLimit", "DailyBudget"} {
				setR13ProviderLimit(t, &cfg, field, 100)
			}
			setR13ProviderLimit(t, &cfg, tc.field, 2)
			provider, err := NewProvider(cfg)
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(provider.Handler())
			t.Cleanup(srv.Close)
			for i := 0; i < 3; i++ {
				reason := r13ProviderReason(t, srv.Client(), srv.URL, r13SignedProviderBody(t, controllerPriv, tc.controller(i), tc.node(i), tc.endpoint(i), i+1, now.Unix()))
				if i < 2 && reason == "rate_limited" {
					t.Fatalf("request %d was rate limited before %s budget", i+1, tc.name)
				}
				if i == 2 && reason != "rate_limited" {
					t.Fatalf("third request reason = %q, want %s rate_limited", reason, tc.name)
				}
			}
		})
	}
}

type r13DeadlineConn struct {
	read, wrote bool
}

func (c *r13DeadlineConn) Read([]byte) (int, error)         { c.read = true; return 0, errors.New("unexpected read") }
func (c *r13DeadlineConn) Write(p []byte) (int, error)      { c.wrote = true; return len(p), nil }
func (c *r13DeadlineConn) Close() error                     { return nil }
func (c *r13DeadlineConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *r13DeadlineConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *r13DeadlineConn) SetDeadline(time.Time) error      { return errors.New("deadline install failed") }
func (c *r13DeadlineConn) SetReadDeadline(time.Time) error  { return errors.New("deadline install failed") }
func (c *r13DeadlineConn) SetWriteDeadline(time.Time) error { return errors.New("deadline install failed") }

// R13 RED: a provider cannot continue an exchange when the connection's hard
// deadline could not be installed. The result remains generic and no WAN1 byte
// is written.
func TestR13ProviderDeadlineInstallFailureFailsClosed(t *testing.T) {
	controllerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, providerPriv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := ProviderConfig{ControllerPublicKey: controllerPub, ProviderPrivateKey: providerPriv}
	field := reflect.ValueOf(&cfg).Elem().FieldByName("DialContext")
	if !field.IsValid() {
		t.Fatal("ProviderConfig.DialContext injection seam is missing")
	}
	conn := &r13DeadlineConn{}
	field.Set(reflect.MakeFunc(field.Type(), func([]reflect.Value) []reflect.Value {
		return []reflect.Value{reflect.ValueOf(net.Conn(conn)), reflect.Zero(reflect.TypeOf((*error)(nil)).Elem())}
	}))
	provider, err := NewProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := &providerRequest{
		ProbeID: strings.Repeat("11", 16), ProviderID: strings.Repeat("22", 16), Activation: strings.Repeat("33", 16),
		Endpoint: "198.51.100.7:9", ExpectedSourceIP: "c6336409", ExpiryOpaque: strings.Repeat("44", 16),
		ArmDigest: strings.Repeat("55", 32), NodePublicKey: strings.Repeat("66", 32),
	}
	result := provider.execute(context.Background(), req)
	if result.Reason != "deadline_failed" {
		t.Fatalf("deadline failure reason = %q, want deadline_failed", result.Reason)
	}
	if conn.read || conn.wrote {
		t.Fatalf("deadline failure continued exchange: read=%v wrote=%v", conn.read, conn.wrote)
	}
}
