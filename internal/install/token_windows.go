//go:build windows

package install

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openInstallerTTY() (*os.File, error) {
	if file := os.Stdin; file != nil {
		return file, nil
	}
	return nil, errors.New("interactive token input requires a TTY")
}

func openDescriptorToken(fd int) (*TokenInput, error) {
	if fd < 3 {
		return nil, tokenError(errors.New("token fd must be >= 3"))
	}
	// The caller owns the inherited handle. Duplicate it so TokenInput can
	// close its copy without invalidating a caller-side handle wrapper.
	process := windows.CurrentProcess()
	var ownedHandle windows.Handle
	if err := windows.DuplicateHandle(process, windows.Handle(fd), process, &ownedHandle, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, tokenError(fmt.Errorf("duplicate token fd: %w", err))
	}
	file := os.NewFile(uintptr(ownedHandle), "antinat-enrollment-token-fd")
	if file == nil {
		_ = windows.CloseHandle(ownedHandle)
		return nil, tokenError(errors.New("token fd is invalid"))
	}
	token, err := readTokenBytes(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &TokenInput{token: token, close: file.Close}, nil
}

func openProtectedTokenFile(path string) (*TokenInput, error) {
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, tokenError(errors.New("token file path is invalid"))
	}
	handle, err := windows.CreateFile(wide, windows.GENERIC_READ|windows.READ_CONTROL|windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, tokenError(fmt.Errorf("open token file: %w", err))
	}
	file := os.NewFile(uintptr(handle), "antinat-enrollment-token-file")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, tokenError(errors.New("token file handle is invalid"))
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.NumberOfLinks != 1 {
		_ = file.Close()
		return nil, tokenError(errors.New("token file must be a regular non-reparse file"))
	}
	if err := ensureWindowsHandlePath(path, handle); err != nil {
		_ = file.Close()
		return nil, tokenError(fmt.Errorf("token file path binding failed: %w", err))
	}
	if err := requireOwnerOnlyWindowsACL(handle); err != nil {
		_ = file.Close()
		return nil, tokenError(err)
	}
	token, err := readTokenBytes(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	input := &TokenInput{token: token, path: path}
	input.close = file.Close
	input.commit = func() error {
		disposition := byte(1)
		if err := windows.SetFileInformationByHandle(windows.Handle(file.Fd()), windows.FileDispositionInfo, &disposition, 1); err != nil {
			return tokenError(fmt.Errorf("consume token file: %w", err))
		}
		return nil
	}
	return input, nil
}

// requireOwnerOnlyWindowsACL mirrors the Agent's Windows token check: the
// effective user must own the file and every data-access allow ACE must name
// that same SID. Windows mode bits are not an ACL substitute.
func requireOwnerOnlyWindowsACL(handle windows.Handle) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return errors.New("token file security descriptor is unavailable")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("token file owner is unavailable")
	}
	current, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return errors.New("current Windows token is unavailable")
	}
	defer current.Close()
	user, err := current.GetTokenUser()
	if err != nil || user == nil || !owner.Equals(user.User.Sid) {
		return errors.New("token file owner is not the current user")
	}
	dacl, _, err := sd.DACL()
	control, _, controlErr := sd.Control()
	if controlErr != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("token file DACL inheritance is not disabled")
	}
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return errors.New("token file DACL is unavailable")
	}
	hasOwner := false
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return errors.New("token file DACL contains an unreadable ACE")
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask == 0 || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return errors.New("token file DACL is not a strict protected allow list")
		}
		sid := (*windows.SID)(unsafe.Pointer(uintptr(unsafe.Pointer(ace)) + unsafe.Offsetof(ace.SidStart)))
		if !owner.Equals(sid) {
			return errors.New("token file DACL grants another principal")
		}
		hasOwner = true
	}
	if !hasOwner {
		return errors.New("token file DACL does not grant the owner access")
	}
	return nil
}
