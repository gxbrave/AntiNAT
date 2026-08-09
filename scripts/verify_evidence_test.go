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
