// Command verify-evidence validates one AntiNAT machine-readable evidence record.
//
// The validator intentionally uses only the standard library so it can run in
// a clean checkout before the rest of the dependency graph exists. The
// normative shape is test/evidence/schema.json; the stable error codes here are
// consumed by CI and release tooling.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const schemaVersion = "antinat.evidence/v1"

var (
	planPattern    = regexp.MustCompile(`^P[0-9]{2}$`)
	commitPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	rfc3339Pattern = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)
	allowedResults = map[string]bool{
		"PASS":                  true,
		"SUPPORTED_WITH_LIMITS": true,
		"NO_GO":                 true,
		"FAIL":                  true,
	}
)

func validationError(code, message string) error {
	return fmt.Errorf("%s: %s", code, message)
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return validationError("EVIDENCE_INVALID_JSON", err.Error())
	}

	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return validationError("EVIDENCE_INVALID_JSON", err.Error())
			}
			key, ok := keyToken.(string)
			if !ok {
				return validationError("EVIDENCE_INVALID_JSON", "object member name must be a string")
			}
			if _, exists := seen[key]; exists {
				return validationError("EVIDENCE_DUPLICATE_FIELD", key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
			if err != nil {
				return validationError("EVIDENCE_INVALID_JSON", err.Error())
			}
			return validationError("EVIDENCE_INVALID_JSON", "object is not terminated")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
			if err != nil {
				return validationError("EVIDENCE_INVALID_JSON", err.Error())
			}
			return validationError("EVIDENCE_INVALID_JSON", "array is not terminated")
		}
	default:
		return validationError("EVIDENCE_INVALID_JSON", "unexpected JSON delimiter")
	}
	return nil
}

func rejectDuplicateObjectMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return validationError("EVIDENCE_INVALID_JSON", "multiple JSON values are not allowed")
		}
		return validationError("EVIDENCE_INVALID_JSON", err.Error())
	}
	return nil
}

func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	if err := rejectDuplicateObjectMembers(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil {
		return nil, validationError("EVIDENCE_INVALID_JSON", err.Error())
	}
	if object == nil {
		return nil, validationError("EVIDENCE_INVALID_TYPE", "root must be a JSON object")
	}

	return object, nil
}

func requiredString(object map[string]json.RawMessage, name string) (string, error) {
	raw, ok := object[name]
	if !ok {
		return "", validationError("EVIDENCE_MISSING_FIELD", name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", validationError("EVIDENCE_INVALID_TYPE", name+" must be a string")
	}
	if strings.TrimSpace(value) == "" {
		return "", validationError("EVIDENCE_EMPTY_FIELD", name)
	}
	return value, nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func optionalString(object map[string]json.RawMessage, name string) error {
	raw, ok := object[name]
	if !ok {
		return nil
	}
	if isJSONNull(raw) {
		return validationError("EVIDENCE_INVALID_TYPE", name+" must be a string")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return validationError("EVIDENCE_INVALID_TYPE", name+" must be a string")
	}
	return nil
}

// positiveIntegralJSONNumber matches JSON Schema's integer semantics: a JSON
// number is valid when its mathematical value is a positive integer, even if
// its spelling uses a fractional zero suffix or an exponent.
func positiveIntegralJSONNumber(value string) bool {
	if value == "" || value[0] == '-' {
		return false
	}

	mantissa, exponent, hasExponent := value, "0", false
	if index := strings.IndexAny(value, "eE"); index >= 0 {
		mantissa, exponent, hasExponent = value[:index], value[index+1:], true
	}
	integerPart, fractionalPart := mantissa, ""
	if index := strings.IndexByte(mantissa, '.'); index >= 0 {
		integerPart, fractionalPart = mantissa[:index], mantissa[index+1:]
	}
	digits := integerPart + fractionalPart
	if digits == "" || strings.Trim(digits, "0") == "" {
		return false
	}

	exponentValue := 0
	negativeExponent := false
	if hasExponent {
		if exponent == "" {
			return false
		}
		if exponent[0] == '-' {
			negativeExponent = true
			exponent = exponent[1:]
		} else if exponent[0] == '+' {
			exponent = exponent[1:]
		}
		if exponent == "" {
			return false
		}
		for _, digit := range exponent {
			if digit < '0' || digit > '9' {
				return false
			}
			if exponentValue > len(digits)+len(fractionalPart) {
				exponentValue = len(digits) + len(fractionalPart)
				continue
			}
			exponentValue = exponentValue*10 + int(digit-'0')
			if exponentValue > len(digits)+len(fractionalPart) {
				exponentValue = len(digits) + len(fractionalPart)
			}
		}
	}

	decimalPlaces := len(fractionalPart)
	if negativeExponent {
		decimalPlaces += exponentValue
	} else {
		decimalPlaces -= exponentValue
	}
	if decimalPlaces <= 0 {
		return true
	}
	if decimalPlaces > len(digits) {
		return false
	}
	return strings.HasSuffix(digits, strings.Repeat("0", decimalPlaces))
}

func requiredPositiveInteger(object map[string]json.RawMessage, name string) (json.Number, error) {
	raw, ok := object[name]
	if !ok {
		return "", validationError("EVIDENCE_MISSING_FIELD", name)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", validationError("EVIDENCE_INVALID_TYPE", name+" must be a positive integer")
	}
	number, ok := value.(json.Number)
	if !ok || !positiveIntegralJSONNumber(number.String()) {
		if ok {
			return "", validationError("EVIDENCE_INVALID_VALUE", name+" must be greater than zero")
		}
		return "", validationError("EVIDENCE_INVALID_TYPE", name+" must be a positive integer")
	}
	return number, nil
}

func validate(data []byte) error {
	if !utf8.Valid(data) {
		return validationError("EVIDENCE_INVALID_JSON", "input must be valid UTF-8")
	}
	object, err := decodeObject(data)
	if err != nil {
		return err
	}

	known := map[string]bool{
		"schema_version": true, "plan": true, "commit_sha": true,
		"command": true, "result": true, "artifact_digest": true,
		"os": true, "timeout": true,
		"started_at": true, "finished_at": true, "summary": true,
		"evidence_paths": true,
	}
	var unknown []string
	for name := range object {
		if !known[name] {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return validationError("EVIDENCE_UNKNOWN_FIELD", strings.Join(unknown, ", "))
	}

	schema, err := requiredString(object, "schema_version")
	if err != nil {
		return err
	}
	if schema != schemaVersion {
		return validationError("EVIDENCE_INVALID_SCHEMA_VERSION", "schema_version must be "+schemaVersion)
	}

	plan, err := requiredString(object, "plan")
	if err != nil {
		return err
	}
	if !planPattern.MatchString(plan) {
		return validationError("EVIDENCE_INVALID_PLAN", "plan must match PNN")
	}

	commit, err := requiredString(object, "commit_sha")
	if err != nil {
		return err
	}
	if !commitPattern.MatchString(commit) {
		return validationError("EVIDENCE_INVALID_SHA", "commit_sha must be 40 lowercase hexadecimal characters")
	}

	if _, err := requiredString(object, "command"); err != nil {
		return err
	}

	result, err := requiredString(object, "result")
	if err != nil {
		return err
	}
	if !allowedResults[result] {
		return validationError("EVIDENCE_INVALID_RESULT", "result must be PASS, SUPPORTED_WITH_LIMITS, NO_GO, or FAIL")
	}

	digest, err := requiredString(object, "artifact_digest")
	if err != nil {
		return err
	}
	if !digestPattern.MatchString(digest) {
		return validationError("EVIDENCE_INVALID_DIGEST", "artifact_digest must match sha256:<64 lowercase hex characters>")
	}

	if _, err := requiredString(object, "os"); err != nil {
		return err
	}
	if _, err := requiredPositiveInteger(object, "timeout"); err != nil {
		return err
	}

	var startedAt, finishedAt time.Time
	var hasStartedAt, hasFinishedAt bool
	for _, name := range []string{"started_at", "finished_at"} {
		_, ok := object[name]
		if !ok {
			continue
		}
		value, err := requiredString(object, name)
		if err != nil {
			return err
		}
		if !rfc3339Pattern.MatchString(value) {
			return validationError("EVIDENCE_INVALID_TIMESTAMP", name+" must be RFC3339")
		}
		normalized := []byte(value)
		normalized[10] = 'T'
		if normalized[len(normalized)-1] == 'z' {
			normalized[len(normalized)-1] = 'Z'
		}
		parsed, err := time.Parse(time.RFC3339, string(normalized))
		if err != nil {
			return validationError("EVIDENCE_INVALID_TIMESTAMP", name+" must be RFC3339")
		}
		if name == "started_at" {
			startedAt, hasStartedAt = parsed, true
		} else {
			finishedAt, hasFinishedAt = parsed, true
		}
	}
	if hasStartedAt && hasFinishedAt && finishedAt.Before(startedAt) {
		return validationError("EVIDENCE_INVALID_TIMESTAMP_ORDER", "finished_at must not be earlier than started_at")
	}
	if err := optionalString(object, "summary"); err != nil {
		return err
	}
	if raw, ok := object["evidence_paths"]; ok {
		if isJSONNull(raw) {
			return validationError("EVIDENCE_INVALID_TYPE", "evidence_paths must be an array of strings")
		}
		var paths []string
		if err := json.Unmarshal(raw, &paths); err != nil {
			return validationError("EVIDENCE_INVALID_TYPE", "evidence_paths must be an array of strings")
		}
		for i, path := range paths {
			if strings.TrimSpace(path) == "" {
				return validationError("EVIDENCE_EMPTY_FIELD", fmt.Sprintf("evidence_paths[%d]", i))
			}
		}
	}
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "EVIDENCE_USAGE: usage: verify-evidence <record.json>")
		os.Exit(2)
	}
	path := os.Args[1]
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "EVIDENCE_READ_ERROR: %s: %v\n", path, err)
		os.Exit(1)
	}
	if err := validate(data); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", path, err)
		os.Exit(1)
	}
	fmt.Printf("PASS %s: evidence record is valid\n", path)
}
