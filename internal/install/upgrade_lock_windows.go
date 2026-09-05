//go:build windows

package install

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type upgradeLock struct {
	mutex windows.Handle
}

func acquireUpgradeLock(root string) (*upgradeLock, error) {
	digest := sha256.Sum256([]byte(root))
	name, err := windows.UTF16PtrFromString("Global\\AntiNAT-Upgrade-" + hex.EncodeToString(digest[:]))
	if err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, fmt.Errorf("identify current Windows user for upgrade mutex: %w", err)
	}
	// Keep the named barrier usable by the installer identity, local
	// administrators, and LocalSystem while excluding unrelated users.
	sd, err := windows.SecurityDescriptorFromString(
		"D:P(A;;GA;;;" + user.User.Sid.String() + ")(A;;GA;;;BA)(A;;GA;;;SY)",
	)
	if err != nil {
		return nil, fmt.Errorf("build upgrade mutex security descriptor: %w", err)
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	mutex, err := windows.CreateMutex(sa, true, name)
	runtime.KeepAlive(sd)
	if err != nil {
		if mutex != 0 {
			_ = windows.CloseHandle(mutex)
		}
		if err == windows.ERROR_ALREADY_EXISTS {
			return nil, fmt.Errorf("upgrade advisory mutex is held")
		}
		return nil, err
	}
	return &upgradeLock{mutex: mutex}, nil
}

func releaseUpgradeLock(lock *upgradeLock) {
	if lock == nil || lock.mutex == 0 {
		return
	}
	_ = windows.ReleaseMutex(lock.mutex)
	_ = windows.CloseHandle(lock.mutex)
}
