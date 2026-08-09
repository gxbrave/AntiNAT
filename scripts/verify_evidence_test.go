package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readEvidenceFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "test", "evidence", "fixtures", name))
	if err != nil {
		t.Fatalf("read fixture %q: %v", name, err)
	}
	return data
}

func TestValidateRejectsDuplicateObjectMemberNames(t *testing.T) {
	err := validate(readEvidenceFixture(t, "duplicate-result.json"))
	if err == nil || !strings.Contains(err.Error(), "EVIDENCE_DUPLICATE_FIELD") {
		t.Fatalf("validate() error = %v, want EVIDENCE_DUPLICATE_FIELD", err)
	}
}

func TestValidateRejectsFinishedAtBeforeStartedAt(t *testing.T) {
	err := validate(readEvidenceFixture(t, "reversed-timestamps.json"))
	if err == nil || !strings.Contains(err.Error(), "EVIDENCE_INVALID_TIMESTAMP_ORDER") {
		t.Fatalf("validate() error = %v, want EVIDENCE_INVALID_TIMESTAMP_ORDER", err)
	}
}

func TestValidateRequiresDocumentedOSEvidenceFields(t *testing.T) {
	for _, test := range []struct {
		name string
		want string
	}{
		{name: "missing-os.json", want: "EVIDENCE_MISSING_FIELD: os"},
		{name: "missing-timeout.json", want: "EVIDENCE_MISSING_FIELD: timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validate(readEvidenceFixture(t, test.name))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validate() error = %v, want %s", err, test.want)
			}
		})
	}
}

func TestValidateRejectsExplicitNullOptionalFields(t *testing.T) {
	for _, test := range []struct {
		name string
		want string
	}{
		{name: "null-summary.json", want: "EVIDENCE_INVALID_TYPE: summary"},
		{name: "null-evidence-paths.json", want: "EVIDENCE_INVALID_TYPE: evidence_paths"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validate(readEvidenceFixture(t, test.name))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validate() error = %v, want %s", err, test.want)
			}
		})
	}
}

func TestWorkflowUsesSupportedUTCBuildDateSource(t *testing.T) {
	workflow, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	contents := string(workflow)
	if strings.Contains(contents, "github.run_started_at") {
		t.Fatal("workflow must not use unsupported github.run_started_at context")
	}
	for _, required := range []string{
		`DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"`,
		`test -n "$DATE"`,
		`DATE="$DATE"`,
	} {
		if !strings.Contains(contents, required) {
			t.Fatalf("workflow missing supported build-date assertion %q", required)
		}
	}
}
func TestValidateAcceptsValidEvidenceFixture(t *testing.T) {
	if err := validate(readEvidenceFixture(t, "pass.json")); err != nil {
		t.Fatalf("validate() valid fixture error = %v", err)
	}
}

func TestValidateRejectsMissingEvidenceFields(t *testing.T) {
	for _, test := range []struct {
		name string
		want string
	}{
		{name: "missing-commit-sha.json", want: "EVIDENCE_MISSING_FIELD: commit_sha"},
		{name: "missing-command.json", want: "EVIDENCE_MISSING_FIELD: command"},
		{name: "missing-result.json", want: "EVIDENCE_MISSING_FIELD: result"},
		{name: "missing-artifact-digest.json", want: "EVIDENCE_MISSING_FIELD: artifact_digest"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validate(readEvidenceFixture(t, test.name))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validate() error = %v, want %s", err, test.want)
			}
		})
	}
}

func TestValidateRejectsInvalidUTF8Evidence(t *testing.T) {
	err := validate(readEvidenceFixture(t, "invalid-utf8.json"))
	if err == nil || !strings.Contains(err.Error(), "EVIDENCE_INVALID_JSON") {
		t.Fatalf("validate() error = %v, want EVIDENCE_INVALID_JSON", err)
	}
}

func TestValidateAcceptsIntegralJSONNumberTimeout(t *testing.T) {
	if err := validate(readEvidenceFixture(t, "timeout-integral-float.json")); err != nil {
		t.Fatalf("validate() integral JSON number error = %v", err)
	}
}

func TestPositiveIntegralJSONNumberMatchesDocumentedRule(t *testing.T) {
	for _, test := range []struct {
		value string
		valid bool
	}{
		{value: "600", valid: true},
		{value: "600.0", valid: true},
		{value: "6e2", valid: true},
		{value: "1000e-2", valid: true},
		{value: "1.5", valid: false},
		{value: "0", valid: false},
		{value: "-1", valid: false},
	} {
		t.Run(test.value, func(t *testing.T) {
			if got := positiveIntegralJSONNumber(test.value); got != test.valid {
				t.Fatalf("positiveIntegralJSONNumber(%q) = %v, want %v", test.value, got, test.valid)
			}
		})
	}
}

func TestValidateAcceptsLowercaseRFC3339Markers(t *testing.T) {
	if err := validate(readEvidenceFixture(t, "lowercase-rfc3339.json")); err != nil {
		t.Fatalf("validate() lowercase RFC3339 error = %v", err)
	}
}

func TestValidateRejectsWhitespaceOnlyEvidenceValues(t *testing.T) {
	for _, name := range []string{
		"whitespace-command.json",
		"whitespace-os.json",
		"whitespace-evidence-path.json",
	} {
		t.Run(name, func(t *testing.T) {
			err := validate(readEvidenceFixture(t, name))
			if err == nil || !strings.Contains(err.Error(), "EVIDENCE_EMPTY_FIELD") {
				t.Fatalf("validate() error = %v, want EVIDENCE_EMPTY_FIELD", err)
			}
		})
	}
}

func TestValidateRejectsOutOfRangeRFC3339Offsets(t *testing.T) {
	for _, name := range []string{
		"invalid-offset-hour.json",
		"invalid-offset-minute.json",
	} {
		t.Run(name, func(t *testing.T) {
			err := validate(readEvidenceFixture(t, name))
			if err == nil || !strings.Contains(err.Error(), "EVIDENCE_INVALID_TIMESTAMP") {
				t.Fatalf("validate() error = %v, want EVIDENCE_INVALID_TIMESTAMP", err)
			}
		})
	}
}
