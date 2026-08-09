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
)

const schemaVersion = "antinat.evidence/v1"

var (
	planPattern    = regexp.MustCompile(`^P[0-9]{2}$`)
	commitPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
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

func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil {
		return nil, validationError("EVIDENCE_INVALID_JSON", err.Error())
	}
	if object == nil {
		return nil, validationError("EVIDENCE_INVALID_TYPE", "root must be a JSON object")
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, validationError("EVIDENCE_INVALID_JSON", "multiple JSON values are not allowed")
		}
		return nil, validationError("EVIDENCE_INVALID_JSON", err.Error())
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

func optionalString(object map[string]json.RawMessage, name string) error {
	raw, ok := object[name]
	if !ok {
		return nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return validationError("EVIDENCE_INVALID_TYPE", name+" must be a string")
	}
	return nil
}

func validate(data []byte) error {
	object, err := decodeObject(data)
	if err != nil {
		return err
	}

	known := map[string]bool{
		"schema_version": true, "plan": true, "commit_sha": true,
		"command": true, "result": true, "artifact_digest": true,
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

	for _, name := range []string{"started_at", "finished_at"} {
		_, ok := object[name]
		if !ok {
			continue
		}
		value, err := requiredString(object, name)
		if err != nil {
			return err
		}
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			return validationError("EVIDENCE_INVALID_TIMESTAMP", name+" must be RFC3339")
		}
	}
	if err := optionalString(object, "summary"); err != nil {
		return err
	}
	if raw, ok := object["evidence_paths"]; ok {
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
