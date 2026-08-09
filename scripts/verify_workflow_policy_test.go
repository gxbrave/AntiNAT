package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func workflowJobs(t *testing.T) (string, map[string]string) {
	t.Helper()
	workflow, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	contents := string(workflow)
	jobs := make(map[string]string)
	inJobs := false
	current := ""
	for _, line := range strings.Split(contents, "\n") {
		if line == "jobs:" {
			inJobs = true
			continue
		}
		if !inJobs {
			continue
		}
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && strings.HasSuffix(line, ":") {
			current = strings.TrimSuffix(strings.TrimSpace(line), ":")
			jobs[current] = ""
		}
		if current != "" {
			jobs[current] += line + "\n"
		}
	}
	return contents, jobs
}

func TestWorkflowPolicy(t *testing.T) {
	contents, jobs := workflowJobs(t)

	if strings.Contains(contents, "pull_request_target") {
		t.Fatal("workflow must not use privileged pull_request_target events")
	}
	if !strings.Contains(contents, "  pull_request:\n") {
		t.Fatal("workflow must use the fork-safe pull_request event")
	}
	if !strings.Contains(contents, "permissions:\n  contents: read\n") {
		t.Fatal("workflow must declare read-only contents permissions")
	}
	if strings.Contains(contents, "contents: write") || strings.Contains(contents, "permissions: write-all") {
		t.Fatal("workflow must not grant write permissions")
	}
	if regexp.MustCompile(`(?m)^\s+[A-Za-z-]+: write\s*$`).MatchString(contents) {
		t.Fatal("workflow must not grant any writable permission scope")
	}

	for _, required := range []string{"pr-fast", "pr-integration", "windows-pr"} {
		job, ok := jobs[required]
		if !ok {
			t.Fatalf("workflow missing required job %q", required)
		}
		timeout := regexp.MustCompile(`(?m)^    timeout-minutes: ([0-9]+)$`).FindStringSubmatch(job)
		if len(timeout) != 2 {
			t.Fatalf("job %q must declare a timeout", required)
		}
		value, err := strconv.Atoi(timeout[1])
		if err != nil || value <= 0 {
			t.Fatalf("job %q timeout must be positive, got %q", required, timeout[1])
		}
	}

	shaPattern := regexp.MustCompile(`^[0-9a-f]{40}(?:\s|$)`)
	for _, line := range strings.Split(contents, "\n") {
		if !strings.Contains(line, "uses:") {
			continue
		}
		uses := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "uses:"))
		at := strings.LastIndex(uses, "@")
		if at < 0 || !shaPattern.MatchString(uses[at+1:]) {
			t.Fatalf("workflow action must be pinned to a full commit SHA: %s", strings.TrimSpace(line))
		}
	}

	for _, required := range []string{
		"retention-days: 7",
		"if-no-files-found: error",
		"DATE=\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"",
		"test -n \"$DATE\"",
	} {
		if !strings.Contains(contents, required) {
			t.Fatalf("workflow missing required policy %q", required)
		}
	}
}

func TestWorkflowRunsPolicyRegression(t *testing.T) {
	contents, _ := workflowJobs(t)
	if !strings.Contains(contents, "go test ./scripts -run TestWorkflowPolicy -count=1") {
		t.Fatal("pr-fast must execute the committed workflow policy regression")
	}
}
