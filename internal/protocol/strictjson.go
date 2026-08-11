// Strict JSON payload decoding (docs/protocol.md §3.4).
//
// Every JSON payload is validated with a strict decoder before any semantic
// use: a single JSON object (no top-level arrays, no trailing garbage), no
// duplicate keys, no unknown fields against the per-message schema, nesting
// depth bounded at 16, and all numbers finite integers within the int64
// range (excluding int64 min). Payload size is bounded by maxPayloadBytes.
package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Stable machine-readable error codes for the strict JSON rules. Callers
// match on these strings or on the sentinel errors below.
const (
	CodeDuplicateKey    = "duplicate_key"
	CodeUnknownField    = "unknown_field"
	CodeTooDeep         = "depth_exceeded"
	CodeNumberOverflow  = "number_overflow"
	CodeTrailingGarbage = "trailing_garbage"
	CodeMalformed       = "malformed"
	CodeNotObject       = "not_object"
	CodeEmpty           = "empty"
	CodeKindMismatch    = "kind_mismatch"
	CodeUnexpectedToken = "unexpected_token"
)

// Stable strict-JSON rejection reasons (errors.Is-compatible).
var (
	ErrEmptyPayload    = errors.New("protocol: json payload is empty")
	ErrDuplicateKey    = errors.New("protocol: duplicate JSON key")
	ErrUnknownField    = errors.New("protocol: unknown JSON field")
	ErrJSONTooDeep     = errors.New("protocol: json nesting depth exceeded")
	ErrNumberOverflow  = errors.New("protocol: json number out of range")
	ErrTrailingGarbage = errors.New("protocol: trailing content after JSON object")
	ErrMalformedJSON   = errors.New("protocol: malformed JSON")
	ErrNotObject       = errors.New("protocol: json payload must be a single object")
	ErrKindMismatch    = errors.New("protocol: json field kind mismatch")
	ErrUnexpectedToken = errors.New("protocol: unexpected JSON token")
)

// StrictJSONError carries a stable machine-readable code plus the wrapped
// sentinel reason and the offending field, when applicable.
type StrictJSONError struct {
	Code_ string
	Field string
	Err   error
}

func (e *StrictJSONError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("protocol: strict json %s: field %q: %v", e.Code_, e.Field, e.Err)
	}
	return fmt.Sprintf("protocol: strict json %s: %v", e.Code_, e.Err)
}

func (e *StrictJSONError) Unwrap() error { return e.Err }

// Code returns the stable machine-readable code.
func (e *StrictJSONError) Code() string { return e.Code_ }

// StrictJSONCode returns the stable code of a strict-JSON error, or "" if err
// is nil or not a strict-JSON error.
func StrictJSONCode(err error) string {
	if err == nil {
		return ""
	}
	var se *StrictJSONError
	if errors.As(err, &se) {
		return se.Code()
	}
	return ""
}

// FieldKind constrains the accepted value type of a schema field.
type FieldKind int

const (
	KindString FieldKind = iota
	KindInt
	KindBool
	KindHex
	KindStringArray
	KindObject
	KindAny
)

// ValidateStrictJSON parses payload as a strict JSON object with the allowed
// field set. A nil schema permits any field name but still enforces shape
// rules (duplicate keys, depth, number bounds, no trailing garbage).
func ValidateStrictJSON(payload []byte, schema map[string]FieldKind) error {
	_, err := decodeStrict(payload, schema)
	return err
}

// DecodeStrictJSON validates payload strictly and returns the decoded object
// with numbers converted to int64.
func DecodeStrictJSON(payload []byte, schema map[string]FieldKind) (map[string]any, error) {
	return decodeStrict(payload, schema)
}

func decodeStrict(payload []byte, schema map[string]FieldKind) (map[string]any, error) {
	if len(payload) == 0 {
		return nil, &StrictJSONError{Code_: CodeEmpty, Err: ErrEmptyPayload}
	}
	if len(payload) > MaxPayloadBytes {
		return nil, &StrictJSONError{Code_: CodeMalformed, Err: fmt.Errorf("%w: %d bytes > %d", ErrMalformedJSON, len(payload), MaxPayloadBytes)}
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	tok, err := d.Token()
	if err != nil {
		return nil, jsonDecodeError(err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, &StrictJSONError{Code_: CodeNotObject, Err: ErrNotObject}
	}
	out := map[string]any{}
	if err := walkObject(d, schema, 0, out); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		// The object parsed completely; any remaining content — including
		// syntactically invalid bytes — is trailing garbage.
		return nil, &StrictJSONError{Code_: CodeTrailingGarbage, Err: ErrTrailingGarbage}
	}
	return out, nil
}

func jsonDecodeError(err error) error {
	var syn *json.SyntaxError
	if errors.As(err, &syn) {
		return &StrictJSONError{Code_: CodeMalformed, Err: ErrMalformedJSON}
	}
	return &StrictJSONError{Code_: CodeMalformed, Err: err}
}

func walkObject(d *json.Decoder, schema map[string]FieldKind, depth int, out map[string]any) error {
	if depth > MaxJSONDepth {
		return &StrictJSONError{Code_: CodeTooDeep, Err: ErrJSONTooDeep}
	}
	seen := map[string]bool{}
	for {
		tok, err := d.Token()
		if err != nil {
			if err == io.EOF {
				return &StrictJSONError{Code_: CodeMalformed, Err: ErrMalformedJSON}
			}
			return jsonDecodeError(err)
		}
		if delim, ok := tok.(json.Delim); ok && delim == '}' {
			return nil
		}
		key, ok := tok.(string)
		if !ok {
			return &StrictJSONError{Code_: CodeUnexpectedToken, Err: ErrUnexpectedToken}
		}
		if seen[key] {
			return &StrictJSONError{Code_: CodeDuplicateKey, Field: key, Err: ErrDuplicateKey}
		}
		seen[key] = true
		kind, allowed := schema[key]
		if !allowed {
			if schema == nil {
				kind = KindAny
			} else {
				return &StrictJSONError{Code_: CodeUnknownField, Field: key, Err: ErrUnknownField}
			}
		}
		val, err := walkValue(d, kind, depth+1)
		if err != nil {
			return err
		}
		out[key] = val
	}
}

func walkValue(d *json.Decoder, kind FieldKind, depth int) (any, error) {
	if depth > MaxJSONDepth {
		return nil, &StrictJSONError{Code_: CodeTooDeep, Err: ErrJSONTooDeep}
	}
	tok, err := d.Token()
	if err != nil {
		if err == io.EOF {
			return nil, &StrictJSONError{Code_: CodeMalformed, Err: ErrMalformedJSON}
		}
		return nil, jsonDecodeError(err)
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			obj := map[string]any{}
			if err := walkObject(d, nil, depth, obj); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for {
				t, e := d.Token()
				if e != nil {
					if e == io.EOF {
						return nil, &StrictJSONError{Code_: CodeMalformed, Err: ErrMalformedJSON}
					}
					return nil, jsonDecodeError(e)
				}
				if delim, ok := t.(json.Delim); ok && delim == ']' {
					return arr, nil
				}
				if err := checkArrayElement(t); err != nil {
					return nil, err
				}
				arr = append(arr, t)
			}
		default:
			return nil, &StrictJSONError{Code_: CodeUnexpectedToken, Err: ErrUnexpectedToken}
		}
	case string:
		switch kind {
		case KindInt:
			return nil, &StrictJSONError{Code_: CodeKindMismatch, Err: ErrKindMismatch}
		case KindHex:
			if _, err := hex.DecodeString(v); err != nil {
				return nil, &StrictJSONError{Code_: CodeKindMismatch, Field: "", Err: fmt.Errorf("%w: %q is not hex", ErrKindMismatch, v)}
			}
		case KindStringArray:
			return nil, &StrictJSONError{Code_: CodeKindMismatch, Err: ErrKindMismatch}
		}
		return v, nil
	case json.Number:
		if kind == KindString {
			return nil, &StrictJSONError{Code_: CodeKindMismatch, Err: ErrKindMismatch}
		}
		if !IsBoundedJSONNumber(v) {
			return nil, &StrictJSONError{Code_: CodeNumberOverflow, Err: fmt.Errorf("%w: %s", ErrNumberOverflow, v.String())}
		}
		i, err := v.Int64()
		if err != nil {
			return nil, &StrictJSONError{Code_: CodeNumberOverflow, Err: fmt.Errorf("%w: %s", ErrNumberOverflow, v.String())}
		}
		return i, nil
	case bool:
		if kind == KindString || kind == KindInt {
			return nil, &StrictJSONError{Code_: CodeKindMismatch, Err: ErrKindMismatch}
		}
		return v, nil
	case nil:
		return nil, nil
	default:
		return nil, &StrictJSONError{Code_: CodeUnexpectedToken, Err: ErrUnexpectedToken}
	}
}

func checkArrayElement(tok json.Token) error {
	switch v := tok.(type) {
	case json.Number:
		if !IsBoundedJSONNumber(v) {
			return &StrictJSONError{Code_: CodeNumberOverflow, Err: fmt.Errorf("%w: %s", ErrNumberOverflow, v.String())}
		}
	case string, bool, nil:
		return nil
	case json.Delim:
		return &StrictJSONError{Code_: CodeUnexpectedToken, Err: ErrUnexpectedToken}
	default:
		return &StrictJSONError{Code_: CodeUnexpectedToken, Err: ErrUnexpectedToken}
	}
	return nil
}

// IsBoundedJSONNumber reports whether n is a finite integer within the int64
// range, excluding int64 min (-9223372036854775808); fractional and
// exponential forms are rejected.
func IsBoundedJSONNumber(n json.Number) bool {
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		return false
	}
	if strings.HasPrefix(s, "-") {
		s = s[1:]
	}
	if len(s) == 0 {
		return false
	}
	const maxI64 = "9223372036854775807"
	if len(s) < len(maxI64) {
		return true
	}
	if len(s) > len(maxI64) {
		return false
	}
	return s <= maxI64
}
