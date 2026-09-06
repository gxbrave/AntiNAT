package sqlite_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func driverDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs("driver")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDriverPrototype(t *testing.T) {
	cmd := exec.Command("go", "test", "-count=1", "./...")
	cmd.Dir = driverDir(t)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nested driver tests: %v\n%s", err, output)
	}
	t.Logf("nested driver tests:\n%s", output)
}

func TestDriverCrossBuildsWithoutCGO(t *testing.T) {
	targets := []struct {
		goos   string
		goarch string
		suffix string
	}{
		{goos: "linux", goarch: "amd64"},
		{goos: "windows", goarch: "amd64", suffix: ".exe"},
	}
	for _, target := range targets {
		t.Run(target.goos+"-"+target.goarch, func(t *testing.T) {
			outputPath := filepath.Join(t.TempDir(), "sqlite-driver"+target.suffix)
			cmd := exec.Command("go", "build", "-trimpath", "-o", outputPath, ".")
			cmd.Dir = driverDir(t)
			cmd.Env = append(os.Environ(),
				"GOWORK=off",
				"CGO_ENABLED=0",
				"GOOS="+target.goos,
				"GOARCH="+target.goarch,
			)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("cross-build: %v\n%s", err, output)
			}
			if info, err := os.Stat(outputPath); err != nil || info.Size() == 0 {
				t.Fatalf("cross-build output missing or empty: info=%v err=%v", info, err)
			}
		})
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Logf("host is %s/%s; cross-build result is build-only evidence", runtime.GOOS, runtime.GOARCH)
	}
}
