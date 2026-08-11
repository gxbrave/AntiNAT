package state_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func prototypeDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs("prototype")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStatePrototype(t *testing.T) {
	cmd := exec.Command("go", "test", "-race", "-count=1", "./...")
	cmd.Dir = prototypeDir(t)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nested state tests: %v\n%s", err, output)
	}
	t.Logf("nested state tests:\n%s", output)
}

func TestStatePrototypeCrossBuildsForWindows(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "state.test.exe")
	cmd := exec.Command("go", "test", "-c", "-o", outputPath, ".")
	cmd.Dir = prototypeDir(t)
	cmd.Env = append(os.Environ(),
		"GOWORK=off",
		"CGO_ENABLED=0",
		"GOOS=windows",
		"GOARCH=amd64",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Windows cross-build: %v\n%s", err, output)
	}
	if info, err := os.Stat(outputPath); err != nil || info.Size() == 0 {
		t.Fatalf("cross-build output missing or empty: info=%v err=%v", info, err)
	}
}
