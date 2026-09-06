//go:build !windows

package install

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestTransactionalUpgradeRestoresFileOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing test-file ownership requires root")
	}
	root := t.TempDir()
	stage := t.TempDir()
	live := filepath.Join(root, "state.db")
	staged := filepath.Join(stage, "state.db")
	if err := os.WriteFile(live, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(live, 12345, 23456); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := TransactionalUpgrade(context.Background(), UpgradeRequest{
		LiveRoot: root, StagingRoot: stage, Files: []string{"state.db"},
		CurrentVersion: 2, PreviousVersion: 1,
		HealthCheck: func(context.Context, string) error { return os.ErrInvalid },
	})
	if err == nil || !result.RolledBack {
		t.Fatalf("upgrade result=%+v err=%v, want a verified rollback", result, err)
	}
	info, err := os.Lstat(live)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 12345 || stat.Gid != 23456 {
		t.Fatalf("restored ownership = %v/%v, want 12345/23456", stat.Uid, stat.Gid)
	}
}
