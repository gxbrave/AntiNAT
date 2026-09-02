package hook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// Runner implements the isolated-JS capability (Story 4): user scripts execute
// with NO network/file/process/reflection/Go-bridge access — a strictly
// bounded expression language over a whitelisted runtime that can only do
// encoding / time / request-description transformations. The broker finalizes
// and signs whatever canonical contribution the script produces; scripts never
// receive secret values.
//
// The interpreter is a purpose-built, sandboxed subset: object/array literals,
// member access, function declarations + closures, for..of, if/else, arithmetic
// and string concatenation, plus the whitelisted runtime below. Anything else
// (require, fetch, process, fs, eval, globals beyond the whitelist) is an
// error — the runner physically has no such natives.
type Runner struct {
	limits Limits
}

// Limits bound one script execution. Zero fields fall back to the defaults so
// a hostile script can never exhaust the controller.
type Limits struct {
	MaxScriptBytes  int
	MaxRequestBytes int
	MaxOutputBytes  int
	MaxSteps        int
	MaxCallDepth    int
	Timeout         time.Duration
}

// DefaultLimits are the frozen runner bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxScriptBytes:  64 << 10, // 64 KiB source
		MaxRequestBytes: 64 << 10, // 64 KiB request description
		MaxOutputBytes:  64 << 10, // 64 KiB log/schema envelope (matches the OS cap)
		MaxSteps:        200_000,
		MaxCallDepth:    64,
		Timeout:         2 * time.Second,
	}
}

// NewRunner builds a runner with the given limits (defaults when zero).
func NewRunner(limits Limits) *Runner {
	if limits.MaxScriptBytes <= 0 {
		limits.MaxScriptBytes = DefaultLimits().MaxScriptBytes
	}
	if limits.MaxRequestBytes <= 0 {
		limits.MaxRequestBytes = DefaultLimits().MaxRequestBytes
	}
	if limits.MaxOutputBytes <= 0 {
		limits.MaxOutputBytes = DefaultLimits().MaxOutputBytes
	}
	if limits.MaxSteps <= 0 {
		limits.MaxSteps = DefaultLimits().MaxSteps
	}
	if limits.MaxCallDepth <= 0 {
		limits.MaxCallDepth = DefaultLimits().MaxCallDepth
	}
	if limits.Timeout <= 0 {
		limits.Timeout = DefaultLimits().Timeout
	}
	return &Runner{limits: limits}
}

// Result is the bounded envelope returned by one script execution.
type Result struct {
	OK           bool           `json:"ok"`
	Contribution map[string]any `json:"contribution,omitempty"`
	Logs         []string       `json:"logs,omitempty"`
	Steps        int            `json:"steps"`
	Err          *ResultError   `json:"error,omitempty"`
}

// ResultError is a machine-readable script error kind.
type ResultError struct {
	Kind    string `json:"kind"` // syntax|reference|type|budget|timeout|schema
	Message string `json:"message"`
}

// Input is the strict runner input envelope: the script, its pinned byte
// identity (sha256), and the request-description JSON.
type Input struct {
	ScriptSHA256 string          `json:"script_sha256"`
	Script       string          `json:"script"`
	Request      json.RawMessage `json:"request"`
}

// Contribution is the canonical signed-string contribution the runner returns
// for the broker to validate and sign (never secret material).
type Contribution struct {
	CanonicalQuery string            `json:"canonical_query"`
	StringToSign   string            `json:"string_to_sign"`
	Params         map[string]string `json:"params,omitempty"`
}

// Run executes one script against a request description. The script SHA256 is
// pinned so a caller (parent/dispatcher) can bind the byte-identity; if the
// hash mismatches the script, the run is refused.
//
// The in-process interpreter is wrapped in a recover() (P2-6): an adversarial
// assertion/overflow/panic inside `Runner.Run` (e.g. a self-referential object
// that would overflow valueToGo, or any future interpreter panic) is converted
// into a bounded runner error instead of aborting the controller process.
func (r *Runner) Run(ctx context.Context, in Input) (result Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			result = fail(ResultError{Kind: "panic", Message: fmt.Sprintf("%v: %v", ErrRunnerPanic, p)})
			err = nil
		}
	}()
	if r == nil || r.limits.Timeout <= 0 {
		return Result{}, errors.New("hook: runner is not configured")
	}
	if len(in.Script) > r.limits.MaxScriptBytes {
		return fail(ResultError{Kind: "schema", Message: "script exceeds the size bound"}), nil
	}
	if len(in.Request) > r.limits.MaxRequestBytes {
		return fail(ResultError{Kind: "schema", Message: "request exceeds the size bound"}), nil
	}
	if in.ScriptSHA256 != "" && sha256HexOfString(in.Script) != in.ScriptSHA256 {
		return fail(ResultError{Kind: "schema", Message: "script byte-identity mismatch (pinned hash)"}), nil
	}
	var request map[string]any
	if err := protocol.DecodeStrictJSONInto(in.Request, &request); err != nil {
		return fail(ResultError{Kind: "schema", Message: "request schema: " + err.Error()}), nil
	}

	runCtx, cancel := context.WithTimeout(ctx, r.limits.Timeout)
	defer cancel()
	vm := &vm{
		limits: r.limits,
		ctx:    runCtx,
		logs:   nil,
	}
	st := vm.executeScript(in.Script, request)
	if !st.ok {
		return st.result, nil
	}
	raw, ok := valueToGo(st.value)
	if !ok {
		return fail(ResultError{Kind: "type", Message: "script returned an unconvertible value"}), nil
	}
	contribution, ok := raw.(map[string]any)
	if !ok {
		return fail(ResultError{Kind: "type", Message: "script must return an object with canonical_query and string_to_sign"}), nil
	}
	if _, ok := contribution["canonical_query"]; !ok {
		return fail(ResultError{Kind: "type", Message: "script return value must include canonical_query"}), nil
	}
	if _, ok := contribution["string_to_sign"]; !ok {
		return fail(ResultError{Kind: "type", Message: "script return value must include string_to_sign"}), nil
	}
	return Result{
		OK:           true,
		Contribution: contribution,
		Logs:         vm.logs,
		Steps:        vm.steps,
	}, nil
}

func (r *Runner) RunContribution(ctx context.Context, in Input) (*Contribution, []string, error) {
	result, err := r.Run(ctx, in)
	if err != nil {
		return nil, nil, err
	}
	if !result.OK {
		if result.Err != nil {
			return nil, nil, fmt.Errorf("hook: runner %s: %s", result.Err.Kind, result.Err.Message)
		}
		return nil, nil, errors.New("hook: runner failed")
	}
	contribution := &Contribution{}
	raw, err := json.Marshal(result.Contribution)
	if err != nil {
		return nil, nil, err
	}
	if err := protocol.DecodeStrictJSONInto(raw, contribution); err != nil {
		return nil, nil, fmt.Errorf("hook: contribution schema: %w", err)
	}
	return contribution, result.Logs, nil
}

func fail(e ResultError) Result {
	return Result{OK: false, Err: &e}
}

func sha256HexOfString(s string) string {
	return sha256Hex(s)
}
