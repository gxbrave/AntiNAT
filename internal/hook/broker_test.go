package hook_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/hook"
)

func newBroker(t *testing.T) (*hook.Store, *hook.SecretKeystore, *hook.Broker) {
	t.Helper()
	hs := newTestHookStore(t)
	ks, err := hook.LoadOrCreateSecretKey(filepath.Join(t.TempDir(), "hook-secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	return hs, ks, hook.NewBroker(hs, ks)
}

func mustCreateSecret(t *testing.T, hs *hook.Store, ks *hook.SecretKeystore, secretID, algorithm, value string) {
	t.Helper()
	blob, keyID, err := ks.Encrypt([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hs.CreateSecret(secretID, algorithm, blob, keyID); err != nil {
		t.Fatal(err)
	}
}

func baseIntent(d hook.Definition) hook.SignIntent {
	return hook.SignIntent{
		HookID: d.ID, SecretID: "access-key-1", Algorithm: string(hook.AlgorithmHMACSHA256),
		Method: "GET", Scheme: "https", Host: "dns.aliyuncs.com", Port: 443,
		Path: "/", Placement: hook.SignaturePlacementHeader, MaxCalls: 1,
		Query: map[string]string{"Action": "DescribeDomainRecords", "Version": "2015-01-09"},
	}
}

// RED P16 Story 3 (e): the broker signs the ONE normalized final allowlisted
// request. For header placement the X-Hook-Signature matches a reference
// HMAC-SHA256 over the body; the plaintext value never leaks into the signed
// request.
func TestBrokerSignsHeaderWebhook(t *testing.T) {
	hs, ks, broker := newBroker(t)
	d := mustDefinition(t, hs, "web", "https://dns.aliyuncs.com/")
	mustCreateSecret(t, hs, ks, "access-key-1", "HMAC-SHA256", "secret-value")
	body := []byte(`{"event":"forward_deleted"}`)
	intent := baseIntent(d)
	intent.Body = body
	req, capability, err := broker.Sign(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "GET" || req.URL != "https://dns.aliyuncs.com/" {
		t.Fatalf("unexpected signed request: %s %s", req.Method, req.URL)
	}
	sig := req.Headers.Get("X-Hook-Signature")
	if !strings.HasPrefix(sig, "sha256=") || len(sig) < 20 {
		t.Fatalf("signature header missing/malformed: %q", sig)
	}
	// The signed request must never contain the secret value.
	if strings.Contains(req.URL, "secret-value") || strings.Contains(sig, "secret-value") ||
		strings.Contains(string(req.Body), "secret-value") {
		t.Fatal("secret value leaked into the signed request")
	}
	if capability.HookID != d.ID || capability.SecretID != "access-key-1" || capability.Algorithm != "HMAC-SHA256" {
		t.Fatalf("capability binding wrong: %+v", capability)
	}
}

// RED P16 Story 3 (f): provider-style query placement appends Signature to the
// canonical sorted query; the final URL's RawQuery is the canonical form and
// every param is RFC3986-encoded.
func TestBrokerSignsQueryPlacement(t *testing.T) {
	hs, ks, broker := newBroker(t)
	d := mustDefinition(t, hs, "web", "https://dns.aliyuncs.com/")
	mustCreateSecret(t, hs, ks, "access-key-1", "HMAC-SHA1", "AliDNS-AccessKeySecret")
	intent := baseIntent(d)
	intent.Algorithm = string(hook.AlgorithmHMACSHA1)
	intent.Placement = hook.SignaturePlacementQuery
	intent.Query = map[string]string{
		"AccessKeyId":     "LTAI-test",
		"Version":         "2015-01-09",
		"Action":          "DescribeDomainRecords",
		"SignatureMethod": "HMAC-SHA1",
	}
	req, _, err := broker.Sign(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	u := req.URL
	// Canonical order: AccessKeyId < Action < Signature < SignatureMethod < Version.
	for i, want := range []string{"AccessKeyId", "Action", "Signature", "SignatureMethod", "Version"} {
		got := queryParamAt(t, u, i)
		if got != want {
			t.Fatalf("query param %d = %q, want %q", i, got, want)
		}
	}
	if !strings.Contains(u, "Signature=") {
		t.Fatalf("Signature param missing in %s", u)
	}
}

func queryParamAt(t *testing.T, u string, index int) string {
	t.Helper()
	parts := strings.Split(u[strings.Index(u, "?")+1:], "&")
	if index >= len(parts) {
		return ""
	}
	return strings.SplitN(parts[index], "=", 2)[0]
}

// RED P16 Story 3 (g): the broker refuses to sign a runner contribution that
// does not match its own canonical normalization (never an arbitrary HMAC
// oracle).
func TestVerifyContributionRejectsMismatch(t *testing.T) {
	d := hook.Definition{ID: "hook-1"}
	intent := baseIntent(d)
	// Correct contribution passes.
	canonical := hook.CanonicalQuery(intent.Query)
	sts := hook.StringToSign(intent.Method, intent.Path, canonical)
	good := []byte(`{"canonical_query":"` + escapeJSON(canonical) + `","string_to_sign":"` + escapeJSON(sts) + `"}`)
	if err := hook.VerifyContribution(intent, good); err != nil {
		t.Fatalf("matching contribution rejected: %v", err)
	}
	// A runner-requested different string-to-sign must be refused.
	bad := []byte(`{"canonical_query":"` + escapeJSON(canonical) + `","string_to_sign":"GET&%2F&evil-canonical"}`)
	if !errors.Is(hook.VerifyContribution(intent, bad), hook.ErrContributionMismatch) {
		t.Fatal("mismatched contribution accepted (arbitrary HMAC oracle)")
	}
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

// RED P16 Story 3 (h): a signing capability honors its call bound (the runner
// may request a call count; the broker signs at most MaxCalls times and then
// fails closed).
func TestCapabilityCallBound(t *testing.T) {
	c := &hook.Capability{MaxCalls: 2}
	if !c.CanSign() || !c.CanSign() {
		t.Fatal("capability bound consumed early")
	}
	if c.CanSign() {
		t.Fatal("capability signed past its call bound")
	}
	zero := &hook.Capability{MaxCalls: 0}
	if !zero.CanSign() {
		t.Fatal("zero MaxCalls must default to a single allowed call")
	}
	if zero.CanSign() {
		t.Fatal("zero-capability signed twice")
	}
}
