package hook_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/hook"
)

const canonicalScript = `
function main(req) {
  var keys = Object.keys(req.params).sort();
  var kvs = [];
  for (var k of keys) {
    kvs.push(runtime.percentEncode(k) + '=' + runtime.percentEncode(req.params[k]));
  }
  var canonical = kvs.join('&');
  var sts = req.method + '&' + runtime.percentEncode(req.path) + '&' + runtime.percentEncode(canonical);
  return {canonical_query: canonical, string_to_sign: sts};
}
`

func canonicalRequest() []byte {
	return []byte(`{
		"event_id": "evt-1",
		"hook_id": "hook-1",
		"method": "GET",
		"path": "/",
		"params": {
			"Version": "2015-01-09",
			"AccessKeyId": "LTAI-test",
			"Action": "DescribeDomainRecords"
		}
	}`)
}

// RED P16 Story 4 (a): a pure-encoding script computes the canonical query with
// sorted params and the canonical string-to-sign, exactly matching the Go
// broker's normalization (the runner and broker share the RFC3986 encoder).
func TestRunnerComputesCanonicalContribution(t *testing.T) {
	r := hook.NewRunner(hook.Limits{})
	in := hook.Input{Script: canonicalScript, Request: canonicalRequest()}
	result, err := r.Run(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("runner failed: %+v", result.Err)
	}
	var contribution struct {
		CanonicalQuery string `json:"canonical_query"`
		StringToSign   string `json:"string_to_sign"`
	}
	raw, _ := json.Marshal(result.Contribution)
	if err := json.Unmarshal(raw, &contribution); err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{
		"Version": "2015-01-09", "AccessKeyId": "LTAI-test",
		"Action": "DescribeDomainRecords",
	}
	wantCanonical := hook.CanonicalQuery(expected)
	wantSTS := hook.StringToSign("GET", "/", wantCanonical)
	if contribution.CanonicalQuery != wantCanonical {
		t.Fatalf("canonical = %q, want %q", contribution.CanonicalQuery, wantCanonical)
	}
	if contribution.StringToSign != wantSTS {
		t.Fatalf("string_to_sign = %q, want %q", contribution.StringToSign, wantSTS)
	}
	if result.Steps <= 0 {
		t.Fatal("no step accounting")
	}
	if !strings.HasPrefix(contribution.CanonicalQuery, "AccessKeyId=") {
		t.Fatalf("canonical query not sorted: %q", contribution.CanonicalQuery)
	}
}

// RED P16 Story 4 (b): the runner has NO network/file/process/reflection bridge
// — each forbidden capability is a runtime/reference error and can never reach
// a resource.
func TestRunnerRejectsBridgeCapabilities(t *testing.T) {
	r := hook.NewRunner(hook.Limits{})
	for _, script := range []string{
		`function main(req){ return runtime.fetch('http://x'); }`,
		`function main(req){ return runtime.require('fs'); }`,
		`function main(req){ return runtime.process.env; }`,
		`function main(req){ return require('child_process'); }`,
		`function main(req){ return fetch('http://x'); }`,
	} {
		in := hook.Input{Script: script, Request: canonicalRequest()}
		result, err := r.Run(context.Background(), in)
		if err != nil {
			t.Fatalf("script %q: err=%v", script, err)
		}
		if result.OK {
			t.Fatalf("script %q unexpectedly succeeded", script)
		}
		if result.Err == nil {
			t.Fatalf("script %q: no error kind", script)
		}
	}
}

// RED P16 Story 4 (c): the strict input schema — an oversized script, a
// missing main, an invalid JSON request, and a pinned-hash mismatch are all
// refused schematically.
func TestRunnerStrictSchema(t *testing.T) {
	r := hook.NewRunner(hook.Limits{MaxScriptBytes: 100})
	big := "var pad='" + strings.Repeat("x", 512) + "'; function main(){return {};}"
	in := hook.Input{Script: big, Request: canonicalRequest()}
	res, err := r.Run(context.Background(), in)
	if err != nil || res.OK || res.Err == nil || res.Err.Kind != "schema" {
		t.Fatalf("oversized script: %+v %v", res, err)
	}

	r2 := hook.NewRunner(hook.Limits{})
	res, err = r2.Run(context.Background(), hook.Input{
		Script:  `function other(){ return {}; }`,
		Request: canonicalRequest(),
	})
	if err != nil || res.OK || res.Err.Kind != "schema" {
		t.Fatalf("missing main: %+v %v", res, err)
	}

	res, err = r2.Run(context.Background(), hook.Input{Script: canonicalScript, Request: []byte(`{"broken`)})
	if err != nil || res.OK || res.Err.Kind != "schema" {
		t.Fatalf("invalid request json: %+v %v", res, err)
	}

	sum := sha256.Sum256([]byte("other-script"))
	withHash := string(hex.EncodeToString(sum[:]))
	in3 := hook.Input{Script: canonicalScript, ScriptSHA256: withHash, Request: canonicalRequest()}
	res, err = r2.Run(context.Background(), in3)
	if err != nil || res.OK || res.Err.Kind != "schema" {
		t.Fatalf("hash mismatch refused? %+v %v (want schema rejection)", res, err)
	}
}

// RED P16 Story 4 (d): bounded execution — an effectively unbounded for..of
// over a self-growing array hits the step budget (time/step bounds hold).
func TestRunnerBoundsExecutionAndOutput(t *testing.T) {
	r := hook.NewRunner(hook.Limits{MaxSteps: 5000})
	res, err := r.Run(context.Background(), hook.Input{
		Script: `
			function main(req) {
				var a = [0];
				for (var i of a) { a.push(i + 1); }
				return {};
			}`,
		Request: canonicalRequest(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Err == nil || res.Err.Kind != "budget" {
		t.Fatalf("budget not enforced: %+v", res)
	}
}

// RED P16 Story 4 (e): runtime.log is bounded by the output byte cap.
func TestRunnerBoundsLogOutput(t *testing.T) {
	r := hook.NewRunner(hook.Limits{MaxOutputBytes: 256})
	res, err := r.Run(context.Background(), hook.Input{
		Script: `function main(req){
			for (var i of [0,1,2,3,4,5,6,7,8,9]) { runtime.log('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'); }
			return {canonical_query:'a=1&z=2', string_to_sign:'GET&%2F&a%3D1%26z%3D2'};
		}`,
		Request: canonicalRequest(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Err == nil || res.Err.Kind != "budget" {
		t.Fatalf("output bound not enforced: %+v", res)
	}
}

// RED P16 Story 4 (f): the request-description never carries secret material
// into the runner (the fixture's request has no secret; the runner cannot read
// one that was never sent).
func TestRunnerRequestHasNoSecretMaterial(t *testing.T) {
	request := canonicalRequest()
	if strings.Contains(string(request), "secret") || strings.Contains(string(request), "AccessKeySecret") {
		t.Fatal("request-description must never carry secret material")
	}
}

// RED repair P1-1: a `return` nested inside if/for/block statements must
// SHORT-CIRCUIT the function to its early-return value. Previously only a
// direct top-level return was honored; a nested return was evaluated and
// discarded, so the function continued and returned the wrong value — and the
// broker then signed/delivered the wrong request.
func TestRunnerNestedReturnShortCircuits(t *testing.T) {
	r := hook.NewRunner(hook.Limits{})
	const script = `
function m(req) {
  if (req.params.a == "stop") {
    return {canonical_query: "a=1", string_to_sign: "GET&%2F&a%3D1", params: {a: "1"}};
  }
  for (var k of [1, 2]) {
    if (k == 2) { return {canonical_query: "b=2", string_to_sign: "GET&%2F&b%3D2", params: {b: "2"}}; }
  }
  return {canonical_query: "c=3", string_to_sign: "GET&%2F&c%3D3", params: {c: "3"}};
}
function main(req) { return m(req); }
`
	req := []byte(`{"params":{"a":"stop"}}`)
	result, err := r.Run(context.Background(), hook.Input{Script: script, Request: req})
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatalf("runner failed: %+v", result.Err)
	}
	var contribution map[string]any
	raw, _ := json.Marshal(result.Contribution)
	_ = json.Unmarshal(raw, &contribution)
	if contribution["canonical_query"] != "a=1" {
		t.Fatalf("nested if-return discarded; got canonical_query=%q, want a=1", contribution["canonical_query"])
	}

	// The for-loop return must also short-circuit (it should win over a later
	// statement).
	req2 := []byte(`{"params":{"a":"continue"}}`)
	badJSON := make(map[string]any)
	if err := json.Unmarshal(req2, &badJSON); err != nil {
		t.Fatal(err)
	}
	result2, err := r.Run(context.Background(), hook.Input{Script: script, Request: req2})
	if err != nil {
		t.Fatal(err)
	}
	if !result2.OK {
		t.Fatalf("runner failed (loop path): %+v", result2.Err)
	}
	raw2, _ := json.Marshal(result2.Contribution)
	var c2 map[string]any
	_ = json.Unmarshal(raw2, &c2)
	if c2["canonical_query"] != "b=2" {
		t.Fatalf("nested for-return discarded; got canonical_query=%q, want b=2", c2["canonical_query"])
	}
}

// RED repair P2-6 (a): MaxCallDepth is enforced in the evaluator call path — a
// deep-recursion script is refused with a budget error and does NOT overflow
// the Go stack.
func TestRunnerMaxCallDepthRefusesDeepRecursion(t *testing.T) {
	r := hook.NewRunner(hook.Limits{MaxCallDepth: 64})
	script := `
function f(n) { if (n > 0) { return f(n - 1) + 1; } return 0; }
function main(req) { return f(100000); }
`
	res, err := r.Run(context.Background(), hook.Input{Script: script, Request: canonicalRequest()})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Err == nil || res.Err.Kind != "budget" {
		t.Fatalf("deep recursion not refused by MaxCallDepth: %+v", res)
	}
}

// RED repair P2-6 (b): the in-process Runner.Run wraps the interpreter in a
// recover() so an adversarial script that panics the interpreter returns a
// bounded runner error (proved by ErrRunnerPanic) instead of aborting the
// test/controller process. The script uses `10 % 0.5`, whose int-coerced
// divisor is 0 and deterministically raises a recoverable "integer divide by
// zero" Go panic inside evalBinary.
func TestRunnerRecoversFromInterpreterPanic(t *testing.T) {
	r := hook.NewRunner(hook.Limits{})
	script := `
function main(req) {
  var x = 10 % 0.5;
  return {canonical_query: 'a=1', string_to_sign: 'GET&%2F&a%3D1'};
}
`
	res, err := r.Run(context.Background(), hook.Input{Script: script, Request: canonicalRequest()})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Err == nil || res.Err.Kind != "panic" {
		t.Fatalf("interpreter panic was not recovered into a bounded runner error: %+v", res)
	}
	if !strings.Contains(res.Err.Message, hook.ErrRunnerPanic.Error()) {
		t.Fatalf("recovered error does not reference ErrRunnerPanic: %q", res.Err.Message)
	}
}

// RED repair P2-6 (c): a script-built CYCLIC structure must fail closed as
// unconvertible instead of overflowing the Go stack (a fatal runtime error that
// a recover() cannot catch). The valueToGo structural recursion is depth-
// bounded so the controller never crashes.
func TestRunnerCyclicObjectFailsClosed(t *testing.T) {
	r := hook.NewRunner(hook.Limits{})
	script := `
function main(req) {
  var o = {n: 1};
  o.self = o;
  return o;
}
`
	res, err := r.Run(context.Background(), hook.Input{Script: script, Request: canonicalRequest()})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Err == nil || res.Err.Kind != "type" {
		t.Fatalf("cyclic result was not refused as unconvertible: %+v", res)
	}
}
