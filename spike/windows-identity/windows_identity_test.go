package windowsidentity

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWindowsIdentityProbeCrossBuilds(t *testing.T) {
	dir, err := filepath.Abs("probe")
	if err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "identity-probe.exe")
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
		t.Fatalf("Windows identity probe cross-build: %v\n%s", err, output)
	}
	if info, err := os.Stat(outputPath); err != nil || info.Size() == 0 {
		t.Fatalf("cross-build output missing or empty: info=%v err=%v", info, err)
	}
}
