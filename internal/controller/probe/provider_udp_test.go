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
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

func TestProviderRequestV2TransportIsSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	req := validProviderRequestForTransport(t, providerRequestSchemaV2, "tcp", priv)
	req.Transport = "udp"
	raw, _ := json.Marshal(req)
	if decoded, err := decodeProviderRequestAt(bytes.NewReader(raw), pub, time.Now()); err == nil || decoded != nil {
		t.Fatal("post-signature tcp-to-udp transport tampering was accepted")
	}
}

func TestProviderRequestV1IsTCPOnly(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	req := validProviderRequestForTransport(t, providerRequestSchema, "", priv)
	raw, _ := json.Marshal(req)
	decoded, err := decodeProviderRequestAt(bytes.NewReader(raw), pub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Transport != "tcp" {
		t.Fatalf("v1 transport = %q, want tcp", decoded.Transport)
	}
}

func TestProviderUnknownTransportPerformsNoNetworkIO(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, providerPriv, _ := ed25519.GenerateKey(rand.Reader)
	dialed := false
	p, err := NewProvider(ProviderConfig{
		ControllerPublicKey: pub, ProviderPrivateKey: providerPriv,
		DialContext: func(context.Context, string, string) (net.Conn, error) { dialed = true; return nil, nil },
		ListenUDP:   func(string, *net.UDPAddr) (*net.UDPConn, error) { dialed = true; return nil, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	req := validProviderRequestForTransport(t, providerRequestSchemaV2, "sctp", priv)
	raw, _ := json.Marshal(req)
	recorder := httptest.NewRecorder()
	p.handleRequest(recorder, newProviderHTTPRequest(raw))
	if dialed {
		t.Fatal("unknown transport caused network I/O")
	}
	var res providerResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Reason != "invalid_transport" {
		t.Fatalf("reason = %q", res.Reason)
	}
}

// Small local request helper avoids standing up an HTTP listener.
func newProviderHTTPRequest(raw []byte) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/probe/v1/request", bytes.NewReader(raw))
}

func validProviderRequestForTransport(t *testing.T, schema, transport string, priv ed25519.PrivateKey) providerRequest {
	t.Helper()
	nodePub := bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize)
	req := providerRequest{Schema: schema, ControllerInstance: "inst", ControllerKeyID: "key", NodePublicKey: hex.EncodeToString(nodePub), NodePublicKeyHash: hex.EncodeToString(hash256(nodePub)), ProbeID: strings.Repeat("22", 16), ProviderID: strings.Repeat("33", 16), Activation: strings.Repeat("44", 16), Transport: transport, Endpoint: "198.51.100.7:9", ExpectedSourceIP: "c6336409", ExpiryOpaque: strings.Repeat("55", 16), TTLMS: 30000, ArmDigest: strings.Repeat("66", 32), TimestampUnix: time.Now().Unix()}
	canonical, err := req.canonical()
	if err != nil {
		t.Fatal(err)
	}
	req.Signature = hex.EncodeToString(ed25519.Sign(priv, canonical))
	return req
}

func TestProviderUDPDatagramExchange(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		accepted   bool
		reason     string
	}{
		{"success", "success", true, "ack_verified"}, {"short", "short", false, "bad_ack"},
		{"oversize", "oversize", false, "bad_ack"}, {"wrong_ack", "wrong", false, "bad_ack"},
	} {
		t.Run(tc.name, func(t *testing.T) { testProviderUDPExchange(t, tc.mode, tc.accepted, tc.reason) })
	}
}

func testProviderUDPExchange(t *testing.T, mode string, wantAccepted bool, wantReason string) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	nodePub, nodePriv, _ := ed25519.GenerateKey(rand.Reader)
	_, providerPriv, _ := ed25519.GenerateKey(rand.Reader)
	controllerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	p, err := NewProvider(ProviderConfig{ControllerPublicKey: controllerPub, ProviderPrivateKey: providerPriv, ExchangeTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	req := &providerRequest{Schema: providerRequestSchemaV2, Transport: "udp", ProbeID: strings.Repeat("11", 16), ProviderID: strings.Repeat("22", 16), Activation: strings.Repeat("33", 16), Endpoint: server.LocalAddr().String(), ExpectedSourceIP: "7f000001", ExpiryOpaque: strings.Repeat("44", 16), ArmDigest: strings.Repeat("55", 32), NodePublicKey: hex.EncodeToString(nodePub)}
	var frame protocol.ProviderFrame
	copy(frame.ArmDigest[:], mustHex(req.ArmDigest))
	copy(frame.ProbeID[:], mustHex(req.ProbeID))
	copy(frame.ProviderID[:], mustHex(req.ProviderID))
	copy(frame.Activation[:], mustHex(req.Activation))
	copy(frame.ExpiryOpaque[:], mustHex(req.ExpiryOpaque))
	frame.Endpoint = req.Endpoint
	if _, err := rand.Read(frame.Challenge[:]); err != nil {
		t.Fatal(err)
	}
	frame.Signature = ed25519.Sign(providerPriv, frame.SigningBytes())
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		n, peer, e := server.ReadFromUDP(buf)
		if e != nil {
			done <- e
			return
		}
		if n == 0 {
			done <- errors.New("empty WAN1 datagram")
			return
		}
		ch := frame.ChallengeHash()
		body := append([]byte(protocol.ProbeMagicACK), frame.ArmDigest[:]...)
		body = append(body, ch[:]...)
		ack := append(body, ed25519.Sign(nodePriv, body)...)
		switch mode {
		case "short":
			ack = ack[:len(ack)-1]
		case "oversize":
			ack = append(ack, 0)
		case "wrong":
			ack[4] ^= 1
			sigBody := ack[:68]
			ack = append(sigBody, ed25519.Sign(nodePriv, sigBody)...)
		}
		_, e = server.WriteToUDP(ack, peer)
		done <- e
	}()
	res := p.executeUDP(context.Background(), req, frame, net.ParseIP("127.0.0.1").To4())
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if res.Accepted != wantAccepted || res.Reason != wantReason {
		t.Fatalf("result=%+v want accepted=%v reason=%q", res, wantAccepted, wantReason)
	}
}
