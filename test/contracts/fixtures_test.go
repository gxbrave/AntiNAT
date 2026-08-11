package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot returns the repository root from the test package directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// Test working directory is the package directory (test/contracts).
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	return root
}

// loadFixtureJSON reads and unmarshals a single frozen fixture.
func loadFixtureJSON(t *testing.T, path string, out any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
}

// walkJSONFiles returns all *.json files under dir sorted by path.
func walkJSONFiles(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	// deterministic order
	for i := 0; i < len(files); i++ {
		for j := i + 1; j < len(files); j++ {
			if files[j] < files[i] {
				files[i], files[j] = files[j], files[i]
			}
		}
	}
	return files
}
