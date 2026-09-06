package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWindowsRestrictedTokenProbeCrossBuilds(t *testing.T) {
	dir, err := filepath.Abs("windowsprobe")
	if err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "sandbox-probe.exe")
	cmd := exec.Command("go", "build", "-trimpath", "-o", outputPath, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GOWORK=off",
		"CGO_ENABLED=0",
		"GOOS=windows",
		"GOARCH=amd64",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Windows restricted-token probe cross-build: %v\n%s", err, output)
	}
	if info, err := os.Stat(outputPath); err != nil || info.Size() == 0 {
		t.Fatalf("cross-build output missing or empty: info=%v err=%v", info, err)
	}
}
