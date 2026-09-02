package hook_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/hook"
)

// RED P16 Story 6: the AliDNS-style provider fixture. The delivery path is
// driven by a lifecycle event that is durably recorded BEFORE the forward
// delivery is enqueued (an in-flight delivery is only ever derived from an
// already-durable state event). Then:
//
//	runner computes the canonical AliDNS request (sorted params, AS-MINUTE
//	timestamp, HMAC-SHA1 string-to-sign) -> broker binds the secret capability
//	+ validates the contribution against its own normalization + signs ->
//	client (stub sender, no network) delivers.
//
// RED: before Story 6 there was NO production DeliveryPreparer composing the
// broker+runner; a scripted delivery had no code path from the queue to a
// signed request (the dispatcher's preparer was nil). This test asserts the
// whole path end-to-end.
func TestAliDnsFullPathFixture(t *testing.T) {
	hs := newTestHookStore(t)
	ks, err := hook.LoadOrCreateSecretKey(filepath.Join(t.TempDir(), "hook-secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	broker := hook.NewBroker(hs, ks)

	// The underlying state event is recorded durably and verified readable
	// before any forward delivery is enqueued.
	if err := hs.AppendAudit("hook_state_recorded", `{"event_id":"evt-aliddns-0001","state":"PENDING"}`); err != nil {
		t.Fatalf("durably record state event: %v", err)
	}
	audit, err := hs.AdminEvents(10)
	if err != nil {
		t.Fatalf("verify durable state event: %v", err)
	}
	found := false
	for _, e := range audit {
		if e == "hook_state_recorded" {
			found = true
		}
	}
	if !found {
		t.Fatal("state event was not durably recorded before delivery")
	}

	d := mustDefinition(t, hs, "aliddns", "https://dns.aliyuncs.com/")
	mustCreateSecret(t, hs, ks, "access-key-1", "HMAC-SHA1", "AliDNS-AccessKeySecret")

	// The request-description is the only data the runner sees: it never
	// contains the secret value.
	payload, err := json.Marshal(map[string]any{
		"event_id": "evt-aliddns-0001",
		"hook_id":  d.ID,
		"method":   "GET",
		"path":     "/",
		"params": map[string]any{
			"AccessKeyId": "LTAI-test",
			"Action":      "DescribeDomainRecords",
			"Version":     "2015-01-09",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := hs.EnqueueEvent(hook.Event{
		HookID:   d.ID,
		EventID:  "evt-aliddns-0001",
		Kind:     "forward_delete",
		NodeID:   "node-1",
		Payload:  payload,
		Script:   []byte(alidnsScript),
		SecretID: "access-key-1",
	})
	if err != nil {
		t.Fatalf("enqueue lifecycle event: %v", err)
	}

	// The dispatcher uses the real production preparer (broker + in-process
	// runner, which is the same interpreter code the OS-isolated child runs)
	// and a stub sender: no network is involved.
	stub := &captureSender{}
	preparer := hook.NewDeliveryPreparer(hs, broker, hook.NewRunner(hook.DefaultLimits()))
	disp := hook.NewDispatcher(hs, stub, preparer, hook.DispatcherConfig{Interval: 0, Batch: 16})
	if n := disp.PumpOnce(); n != 1 {
		t.Fatalf("pump handled %d deliveries, want 1", n)
	}

	got, err := hs.GetDelivery(delivery.ID)
	if err != nil {
		t.Fatalf("get delivery: %v", err)
	}
	if got.State != hook.DeliveryDelivered {
		t.Fatalf("delivery state = %s last_err=%q, want DELIVERED", got.State, got.LastError)
	}
	if got.ScriptB64 == "" {
		t.Fatal("script was not persisted (base64) on the delivery row")
	}
	if stub.req == nil {
		t.Fatal("stub sender captured no request")
	}
	if stub.req.Method != "GET" {
		t.Fatalf("captured method = %s, want GET", stub.req.Method)
	}

	u, err := url.Parse(stub.req.URL)
	if err != nil {
		t.Fatalf("parse captured url: %v", err)
	}
	if u.Scheme != "https" || u.Host != "dns.aliyuncs.com" || u.Path != "/" {
		t.Fatalf("captured url = %q, want https://dns.aliyuncs.com/", stub.req.URL)
	}
	q := u.Query()
	sig := q.Get("Signature")
	if sig == "" {
		t.Fatal("provider-style Signature query param is missing")
	}

	// Canonical sorted order (byte order over the final params incl Signature):
	// AccessKeyId < Action < Signature < SignatureMethod < SignatureNonce <
	// SignatureVersion < Timestamp < Version.
	wantOrder := []string{
		"AccessKeyId", "Action", "Signature", "SignatureMethod",
		"SignatureNonce", "SignatureVersion", "Timestamp", "Version",
	}
	parts := strings.Split(u.RawQuery, "&")
	if len(parts) != len(wantOrder) {
		t.Fatalf("query param count = %d, want %d (%s)", len(parts), len(wantOrder), u.RawQuery)
	}
	for i, want := range wantOrder {
		if !strings.HasPrefix(parts[i], want+"=") {
			t.Fatalf("query param %d = %q, want %s=... (%s)", i, parts[i], want, u.RawQuery)
		}
	}

	// The signature must VERIFY against the plaintext secret when recomputed
	// from the final canonical request (Signature stripped).
	params := map[string]string{}
	for k, vs := range q {
		params[k] = vs[0]
	}
	delete(params, "Signature")
	canonical := hook.CanonicalQuery(params)
	sts := "GET&" + hook.PercentEncode("/") + "&" + hook.PercentEncode(canonical)
	mac := hmac.New(sha1.New, []byte("AliDNS-AccessKeySecret&"))
	mac.Write([]byte(sts))
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if sig != expected {
		t.Fatalf("signature does not verify: got %q want %q", sig, expected)
	}
	// The AS-MINUTE timestamp is present and the contribution used the SAME
	// canonical string (Signature must equal the forward recomputation; the
	// broker signs the runner's verified string-to-sign).
	if q.Get("Timestamp") == "" || len(q.Get("Timestamp")) != len("2006-01-02T15:04Z") {
		t.Fatalf("AS-MINUTE timestamp missing/malformed: %q", q.Get("Timestamp"))
	}

	// The plaintext secret value never leaks into the request: not in the URL,
	// not in the body, not in any header.
	if strings.Contains(stub.req.URL, "AliDNS-AccessKeySecret") ||
		strings.Contains(string(stub.req.Body), "AliDNS-AccessKeySecret") {
		t.Fatal("secret value leaked into the signed request")
	}
	for key, values := range stub.req.Headers {
		for _, v := range values {
			if strings.Contains(v, "AliDNS-AccessKeySecret") {
				t.Fatalf("secret value leaked into header %s", key)
			}
		}
	}
}

// RED P16 Story 6 (composition): the production Service wires the real
// delivery preparer (broker + runner) into the dispatcher — a secret-bound
// webhook (no script) is signed header-placement and delivered through
// Service.PumpOnce with a stub sender. Before Story 6 the Service's dispatcher
// was constructed with a nil preparer and every delivery failed closed.
func TestServiceWiredPreparerSignsWebhook(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "controller.db")
	cst, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cst.Close() })

	stub := &captureSender{}
	svc, err := hook.NewService(hook.ServiceConfig{
		DBPath:  dbPath,
		KeyPath: filepath.Join(t.TempDir(), "hook-secret.key"),
		Sender:  stub,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	svc.SetClock(func() time.Time { return time.Unix(1_700_000_000, 0) })

	d, err := svc.CreateDefinition("web", hook.KindWebhook, "https://example.org/events")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateSecret("access-key-1", "HMAC-SHA256", "secret-value"); err != nil {
		t.Fatal(err)
	}
	delivery, err := svc.EnqueueLifecycleEvent(hook.Event{
		HookID: d.ID, EventID: "evt-1", Kind: "forward_delete", NodeID: "node-1",
		Payload: []byte(`{"event":"forward_deleted"}`), SecretID: "access-key-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := svc.PumpOnce(); n != 1 {
		t.Fatalf("pump handled %d, want 1", n)
	}
	got, err := svc.Store.GetDelivery(delivery.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != hook.DeliveryDelivered {
		t.Fatalf("state = %s last_err=%q, want DELIVERED", got.State, got.LastError)
	}
	if stub.req == nil {
		t.Fatal("no request captured")
	}
	if stub.req.URL != "https://example.org/events" {
		t.Fatalf("url = %q", stub.req.URL)
	}
	if sig := stub.req.Headers.Get("X-Hook-Signature"); !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("secret-bound webhook was not header-signed: %q", sig)
	}
}

// captureSender is the network-free delivery sink: it records the final
// SignedRequest exactly as the client would send it.
type captureSender struct {
	req *hook.SignedRequest
}

func (s *captureSender) Send(_ context.Context, req *hook.SignedRequest) (*hook.SendResult, error) {
	if s != nil {
		s.req = req
	}
	return &hook.SendResult{StatusCode: 200}, nil
}

// alidnsScript is the provider-style fixture script: it adds the real AliDNS
// signing params (AS-MINUTE Timestamp, SignatureMethod/Version, SignatureNonce)
// and returns the canonical sorted query + string-to-sign. It never touches
// the secret value; the broker finalizes and signs.
const alidnsScript = `
function main(req) {
  var p = req.params;
  p.SignatureMethod = 'HMAC-SHA1';
  p.SignatureVersion = '1.0';
  p.SignatureNonce = runtime.nonce();
  p.Timestamp = runtime.ts();
  var canonical = runtime.canonicalQuery(p);
  var sts = req.method + '&' + runtime.percentEncode(req.path) + '&' + runtime.percentEncode(canonical);
  return {canonical_query: canonical, string_to_sign: sts, params: p};
}
`
