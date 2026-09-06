//go:build windows

package install

import "os"

// Windows ACLs are carried by the protected install directories. UID/GID are
// not portable Windows metadata, so the cross-platform manifest leaves these
// fields at zero and relies on the native ACL path.
func snapshotFileOwnership(os.FileInfo) (uint32, uint32, error) { return 0, 0, nil }

func restoreSnapshotFileOwnership(string, uint32, uint32) error { return nil }
