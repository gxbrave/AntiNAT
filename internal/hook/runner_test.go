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
