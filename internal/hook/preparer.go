package hook

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// ScriptRunner executes one script+request envelope and returns the result
// envelope bytes. The production runner is the OS-isolated child
// (cmd/antinat-hook-runner); the in-process interpreter implements the same
// interface for fixtures and tests (identical interpreter code, no OS
// boundary).
type ScriptRunner interface {
	RunEnvelope(ctx context.Context, script []byte, request []byte, limits Limits) ([]byte, error)
}

// RunEnvelope adapts the in-process Runner to the ScriptRunner interface.
func (r *Runner) RunEnvelope(ctx context.Context, script, request []byte, limits Limits) ([]byte, error) {
	result, err := r.Run(ctx, Input{Script: string(script), Request: request})
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

// DeliveryPreparerImpl converts a claimed delivery into the ONE final
// normalized SignedRequest:
//
//   - plain webhook: POST hook.url with the event payload;
//   - secret + no script: broker signs the body (header placement);
//   - secret + script: runner computes the canonical contribution, the broker
//     verifies it against its own normalization and signs (query placement).
//
// Script deliveries fail closed when no ScriptRunner is configured (webhook-only).
type DeliveryPreparerImpl struct {
	store  *Store
	broker *Broker
	runner ScriptRunner
	limits Limits
}

// NewDeliveryPreparer builds the production dispatcher preparer.
func NewDeliveryPreparer(store *Store, broker *Broker, runner ScriptRunner) *DeliveryPreparerImpl {
	return &DeliveryPreparerImpl{store: store, broker: broker, runner: runner, limits: DefaultLimits()}
}

// Prepare satisfies the Dispatcher's DeliveryPreparer interface.
func (p *DeliveryPreparerImpl) Prepare(ctx context.Context, d Delivery) (*SignedRequest, error) {
	def, err := p.store.GetDefinition(d.HookID)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(def.URL)
	if err != nil {
		return nil, fmt.Errorf("hook: parse definition url: %w", err)
	}
	base := &SignedRequest{
		Method:  "POST",
		URL:     def.URL,
		Headers: http.Header{},
		Body:    []byte(d.PayloadJSON),
	}
	base.Headers.Set("Content-Type", "application/json")
	base.Headers.Set("X-Event-ID", d.EventID)
	base.Headers.Set("X-Delivery-ID", d.ID)

	if d.SecretID == "" && d.ScriptB64 == "" {
		return base, nil
	}

	row, err := p.store.GetSecretRow(d.SecretID)
	if err != nil {
		return nil, fmt.Errorf("hook: bound secret for delivery: %w", err)
	}

	if d.ScriptB64 == "" {
		// Header-placement body signature (no runner).
		intent := SignIntent{
			HookID: d.HookID, SecretID: d.SecretID, Algorithm: row.Algorithm,
			Method: "POST", Scheme: u.Scheme, Host: u.Hostname(), Port: portOf(u),
			Path: pathOf(u), Body: []byte(d.PayloadJSON),
			Placement: SignaturePlacementHeader, MaxCalls: 1,
		}
		req, _, err := p.broker.Sign(ctx, intent)
		if err != nil {
			return nil, err
		}
		return mergeHeaders(req, d), nil
	}

	// Scripted provider-style contribution: runner computes, broker verifies +
	// signs. The request-description is in the delivery payload.
	script, err := base64.StdEncoding.DecodeString(d.ScriptB64)
	if err != nil {
		return nil, fmt.Errorf("hook: invalid script encoding: %w", err)
	}
	if p.runner == nil {
		return nil, ErrRunnerUnsupported
	}
	envelope, err := p.runner.RunEnvelope(ctx, script, []byte(d.PayloadJSON), p.limits)
	if err != nil {
		return nil, err
	}
	var out struct {
		OK           bool                       `json:"ok"`
		Contribution map[string]json.RawMessage `json:"contribution"`
		Logs         []string                   `json:"logs"`
		Steps        int                        `json:"steps"`
		Err          *struct {
			Kind    string `json:"kind"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := protocol.DecodeStrictJSONInto(envelope, &out); err != nil {
		return nil, fmt.Errorf("hook: runner envelope: %w", err)
	}
	if !out.OK {
		if out.Err != nil {
			return nil, fmt.Errorf("hook: runner %s: %s", out.Err.Kind, out.Err.Message)
		}
		return nil, errors.New("hook: runner failed")
	}
	var contribution struct {
		CanonicalQuery string            `json:"canonical_query"`
		StringToSign   string            `json:"string_to_sign"`
		Params         map[string]string `json:"params"`
	}
	raw, _ := json.Marshal(out.Contribution)
	if err := protocol.DecodeStrictJSONInto(raw, &contribution); err != nil {
		return nil, fmt.Errorf("hook: contribution: %w", err)
	}
	if len(contribution.Params) == 0 {
		return nil, fmt.Errorf("%w: script contribution has no final params", ErrContributionMismatch)
	}
	intent := SignIntent{
		HookID: d.HookID, SecretID: d.SecretID, Algorithm: row.Algorithm,
		Method: firstNonEmpty(requestMethod(d), "GET"),
		Scheme: u.Scheme, Host: u.Hostname(), Port: portOf(u),
		Path:      firstNonEmpty(requestPath(d), pathOf(u)),
		Query:     contribution.Params,
		Body:      []byte(d.PayloadJSON),
		Placement: SignaturePlacementQuery, MaxCalls: 1,
	}
	// The broker refuses to sign unless the contribution matches its own
	// canonicalization of the SAME final params.
	if err := VerifyContribution(intent, raw); err != nil {
		return nil, err
	}
	req, _, err := p.broker.Sign(ctx, intent)
	if err != nil {
		return nil, err
	}
	return mergeHeaders(req, d), nil
}

func mergeHeaders(req *SignedRequest, d Delivery) *SignedRequest {
	req.Headers.Set("X-Event-ID", d.EventID)
	req.Headers.Set("X-Delivery-ID", d.ID)
	return req
}

func portOf(u *url.URL) int {
	if p := u.Port(); p != "" {
		var port int
		if _, err := fmt.Sscanf(p, "%d", &port); err == nil {
			return port
		}
	}
	if u.Scheme == "http" {
		return 80
	}
	return 443
}

func pathOf(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func requestMethod(d Delivery) string {
	var rd struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal([]byte(d.PayloadJSON), &rd)
	return rd.Method
}

func requestPath(d Delivery) string {
	var rd struct {
		Path string `json:"path"`
	}
	_ = json.Unmarshal([]byte(d.PayloadJSON), &rd)
	return rd.Path
}
