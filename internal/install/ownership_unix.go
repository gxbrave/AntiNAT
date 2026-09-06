//go:build !windows

package install

import (
	"fmt"
	"os"
	"syscall"
)

func snapshotFileOwnership(info os.FileInfo) (uint32, uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, 0, fmt.Errorf("unsupported file ownership metadata")
	}
	return stat.Uid, stat.Gid, nil
}

func restoreSnapshotFileOwnership(path string, uid, gid uint32) error {
	if err := os.Lchown(path, int(uid), int(gid)); err != nil {
		return err
	}
	return nil
}
