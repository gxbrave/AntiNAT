//go:build windows

package install

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errWindowsPurgeReparse = errors.New("refusing to purge a symlink/reparse point")

func finalWindowsHandlePath(handle windows.Handle) (string, error) {
	const maxPathChars = 32768
	buffer := make([]uint16, maxPathChars)
	length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil {
		return "", err
	}
	if length == 0 || length >= uint32(len(buffer)) {
		return "", errors.New("final Windows path exceeds the supported limit")
	}
	return windows.UTF16ToString(buffer[:length]), nil
}

func extendedWindowsPath(path string) string {
	if strings.HasPrefix(path, `\\?\`) {
		return path
	}
	if strings.HasPrefix(path, `\\`) {
		return `\\?\UNC\` + strings.TrimPrefix(path, `\\`)
	}
	return `\\?\` + path
}

func ensureWindowsHandlePath(path string, handle windows.Handle) error {
	canonical, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	canonical = filepath.Clean(canonical)
	if strings.HasPrefix(canonical, `\\.\`) {
		return errors.New("device paths are not valid installer paths")
	}
	actual, err := finalWindowsHandlePath(handle)
	if err != nil {
		return err
	}
	actual = strings.TrimRight(actual, `\`)
	expected := strings.TrimRight(extendedWindowsPath(canonical), `\`)
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("opened path resolves to %q, want %q", actual, expected)
	}
	return nil
}

func verifyOwnershipKeyFile(path string, key []byte) error {
	raw, err := readProtectedFile(path, 4<<20, "ownership key")
	if err != nil {
		return err
	}
	if len(raw) != len(key) || !hmac.Equal(raw, key) {
		return errors.New("ownership key file does not match the supplied key")
	}
	return nil
}

func readProtectedFile(path string, limit int64, label string) ([]byte, error) {
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode %s path: %w", label, err)
	}
	handle, err := windows.CreateFile(
		wide,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	file := os.NewFile(uintptr(handle), "antinat-protected-file")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("%s handle is invalid", label)
	}
	defer file.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, fmt.Errorf("stat %s: %w", label, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, fmt.Errorf("%s is not a regular non-reparse file", label)
	}
	if info.NumberOfLinks != 1 {
		return nil, fmt.Errorf("%s must have one link", label)
	}
	if err := ensureWindowsHandlePath(path, handle); err != nil {
		return nil, fmt.Errorf("%s path binding failed: %w", label, err)
	}
	if err := verifyWindowsPrivateACL(handle, label); err != nil {
		return nil, err
	}
	fileSize := uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)
	if fileSize > uint64(limit) {
		return nil, fmt.Errorf("%s exceeds size limit", label)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds size limit", label)
	}
	return data, nil
}

func verifyWindowsPrivateACL(handle windows.Handle, label string) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		if err == nil {
			err = errors.New("security descriptor is empty")
		}
		return fmt.Errorf("inspect %s ACL: %w", label, err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s ACL is not protected", label)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s ACL owner is unavailable", label)
	}
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("identify current Windows user: %w", err)
	}
	if current == nil || current.User.Sid == nil {
		return fmt.Errorf("identify current Windows user: missing user SID")
	}
	trusted := map[string]bool{
		current.User.Sid.String(): true,
		"S-1-5-18":                true,
		"S-1-5-32-544":            true,
	}
	if !trusted[owner.String()] {
		return fmt.Errorf("%s ACL owner is not trusted", label)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return fmt.Errorf("%s ACL has no explicit protected entries", label)
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return fmt.Errorf("inspect %s ACL entry: %w", label, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return fmt.Errorf("%s ACL contains an inherited or denied entry", label)
		}
		sid := (*windows.SID)(unsafe.Pointer(uintptr(unsafe.Pointer(ace)) + unsafe.Offsetof(ace.SidStart)))
		if !trusted[sid.String()] {
			return fmt.Errorf("%s ACL grants an untrusted principal", label)
		}
	}
	return nil
}

type windowsPurgeEntry struct {
	file     *os.File
	info     windows.ByHandleFileInformation
	children []*windowsPurgeEntry
}

func (entry *windowsPurgeEntry) handle() windows.Handle {
	return windows.Handle(entry.file.Fd())
}

func (entry *windowsPurgeEntry) isDir() bool {
	return entry.info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
}

func (entry *windowsPurgeEntry) close() error {
	if entry == nil || entry.file == nil {
		return nil
	}
	err := entry.file.Close()
	entry.file = nil
	return err
}

func closeWindowsPurgeTree(entry *windowsPurgeEntry) error {
	if entry == nil {
		return nil
	}
	var errs []error
	for _, child := range entry.children {
		if err := closeWindowsPurgeTree(child); err != nil {
			errs = append(errs, err)
		}
	}
	entry.children = nil
	if err := entry.close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func removeOwnedResource(root, relative string) (bool, error) {
	if err := validateRelativeResource(relative); err != nil {
		return false, err
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	rootEntry, err := openWindowsPurgeRoot(root)
	if windowsPurgeIsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer rootEntry.close()

	components := strings.Split(filepath.ToSlash(relative), "/")
	parent := rootEntry
	var parents []*windowsPurgeEntry
	defer func() {
		for i := len(parents) - 1; i >= 0; i-- {
			_ = parents[i].close()
		}
	}()
	for i, component := range components {
		entry, err := openWindowsPurgeEntry(parent.handle(), component)
		if windowsPurgeIsNotExist(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if i < len(components)-1 {
			if !entry.isDir() {
				_ = entry.close()
				return false, fmt.Errorf("purge parent %q is not a directory", component)
			}
			parents = append(parents, entry)
			parent = entry
			continue
		}
		if err := preflightWindowsPurgeEntry(entry); err != nil {
			_ = closeWindowsPurgeTree(entry)
			return false, err
		}
		if err := deleteWindowsPurgeEntry(entry); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func openWindowsPurgeRoot(path string) (*windowsPurgeEntry, error) {
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode purge root: %w", err)
	}
	handle, err := windows.CreateFile(
		wide,
		windows.FILE_READ_ATTRIBUTES|windows.FILE_LIST_DIRECTORY|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), "antinat-purge-root")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("purge root handle is invalid")
	}
	entry := &windowsPurgeEntry{file: file}
	if err := windows.GetFileInformationByHandle(handle, &entry.info); err != nil {
		_ = entry.close()
		return nil, fmt.Errorf("inspect purge root: %w", err)
	}
	if err := validateWindowsPurgeEntry(entry); err != nil {
		_ = entry.close()
		return nil, err
	}
	if !entry.isDir() {
		_ = entry.close()
		return nil, errors.New("purge root is not a directory")
	}
	if err := ensureWindowsHandlePath(path, entry.handle()); err != nil {
		_ = entry.close()
		return nil, fmt.Errorf("purge root path binding failed: %w", err)
	}
	return entry, nil
}

func openWindowsPurgeEntry(parent windows.Handle, name string) (*windowsPurgeEntry, error) {
	access := uint32(windows.FILE_READ_ATTRIBUTES | windows.DELETE | windows.SYNCHRONIZE)
	handle, info, err := openWindowsPurgeHandle(parent, name, access, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), "antinat-purge-entry")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("purge entry handle is invalid")
	}
	entry := &windowsPurgeEntry{file: file, info: info}
	if err := validateWindowsPurgeEntry(entry); err != nil {
		_ = entry.close()
		return nil, err
	}
	if !entry.isDir() {
		return entry, nil
	}

	// A directory needs FILE_LIST_DIRECTORY for the complete preflight walk.
	// Reopen it relative to the same already-open parent, still refusing all
	// reparse traversal.
	if err := entry.close(); err != nil {
		return nil, err
	}
	handle, info, err = openWindowsPurgeHandle(parent, name, access|uint32(windows.FILE_LIST_DIRECTORY), windows.FILE_DIRECTORY_FILE)
	if err != nil {
		return nil, err
	}
	file = os.NewFile(uintptr(handle), "antinat-purge-directory")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("purge directory handle is invalid")
	}
	entry = &windowsPurgeEntry{file: file, info: info}
	if err := validateWindowsPurgeEntry(entry); err != nil {
		_ = entry.close()
		return nil, err
	}
	if !entry.isDir() {
		_ = entry.close()
		return nil, errors.New("purge entry changed from directory")
	}
	return entry, nil
}

func openWindowsPurgeHandle(parent windows.Handle, name string, access, options uint32) (windows.Handle, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, info, fmt.Errorf("encode purge entry: %w", err)
	}
	objectAttributes := &windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var handle windows.Handle
	status := windows.NtCreateFile(
		&handle,
		access,
		objectAttributes,
		&windows.IO_STATUS_BLOCK{},
		nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT|options,
		0,
		0,
	)
	if status != nil {
		return windows.InvalidHandle, info, windowsPurgeOpenError(status)
	}
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, info, fmt.Errorf("inspect purge entry: %w", err)
	}
	return handle, info, nil
}

func validateWindowsPurgeEntry(entry *windowsPurgeEntry) error {
	if entry.info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errWindowsPurgeReparse
	}
	fileType, err := windows.GetFileType(entry.handle())
	if err != nil {
		return fmt.Errorf("inspect purge entry type: %w", err)
	}
	if fileType != windows.FILE_TYPE_DISK {
		return errors.New("refusing to purge a non-disk resource")
	}
	return nil
}

func preflightWindowsPurgeEntry(entry *windowsPurgeEntry) error {
	if err := validateWindowsPurgeEntry(entry); err != nil {
		return err
	}
	if !entry.isDir() {
		return nil
	}
	names, err := entry.file.Readdirnames(-1)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read purge directory: %w", err)
	}
	sort.Strings(names)
	for _, name := range names {
		child, err := openWindowsPurgeEntry(entry.handle(), name)
		if windowsPurgeIsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect purge child %q: %w", name, err)
		}
		if err := preflightWindowsPurgeEntry(child); err != nil {
			_ = closeWindowsPurgeTree(child)
			return fmt.Errorf("inspect purge child %q: %w", name, err)
		}
		entry.children = append(entry.children, child)
	}
	return nil
}

func deleteWindowsPurgeEntry(entry *windowsPurgeEntry) error {
	var errs []error
	for _, child := range entry.children {
		if err := deleteWindowsPurgeEntry(child); err != nil {
			errs = append(errs, err)
		}
	}
	entry.children = nil
	if err := markWindowsPurgeDelete(entry.handle()); err != nil {
		errs = append(errs, err)
	}
	if err := entry.close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func markWindowsPurgeDelete(handle windows.Handle) error {
	type dispositionInformationEx struct {
		Flags uint32
	}
	ex := dispositionInformationEx{Flags: windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE}
	if err := windows.SetFileInformationByHandle(
		handle,
		windows.FileDispositionInfoEx,
		(*byte)(unsafe.Pointer(&ex)),
		uint32(unsafe.Sizeof(ex)),
	); err == nil {
		return nil
	}
	// FileDispositionInfoEx is unavailable on older Windows/filesystems. The
	// legacy form is still handle-bound and never re-resolves a pathname.
	disposition := byte(1)
	if err := windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &disposition, 1); err != nil {
		return fmt.Errorf("mark purge entry for deletion: %w", err)
	}
	return nil
}

func ownedResourceExists(root, relative string) (bool, error) {
	if err := validateRelativeResource(relative); err != nil {
		return false, err
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	rootEntry, err := openWindowsPurgeRoot(root)
	if windowsPurgeIsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer rootEntry.close()
	components := strings.Split(filepath.ToSlash(relative), "/")
	parent := rootEntry
	var parents []*windowsPurgeEntry
	defer func() {
		for i := len(parents) - 1; i >= 0; i-- {
			_ = parents[i].close()
		}
	}()
	for i, component := range components {
		entry, err := openWindowsPurgeEntry(parent.handle(), component)
		if windowsPurgeIsNotExist(err) {
			return false, nil
		}
		if err != nil {
			return true, err
		}
		if i < len(components)-1 {
			if !entry.isDir() {
				_ = entry.close()
				return true, fmt.Errorf("purge parent %q is not a directory", component)
			}
			parents = append(parents, entry)
			parent = entry
			continue
		}
		defer entry.close()
		return true, nil
	}
	return false, nil
}

func windowsPurgeOpenError(err error) error {
	status, ok := err.(windows.NTStatus)
	if !ok {
		return err
	}
	switch status {
	case windows.STATUS_REPARSE_POINT_ENCOUNTERED,
		windows.STATUS_DIRECTORY_IS_A_REPARSE_POINT,
		windows.STATUS_IO_REPARSE_TAG_NOT_HANDLED,
		windows.STATUS_REPARSE_POINT_NOT_RESOLVED:
		return errWindowsPurgeReparse
	default:
		return err
	}
}

func windowsPurgeIsNotExist(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return true
	}
	status, ok := err.(windows.NTStatus)
	if !ok {
		return false
	}
	return status == windows.STATUS_NO_SUCH_FILE || status == windows.STATUS_OBJECT_NAME_NOT_FOUND || status == windows.STATUS_OBJECT_PATH_NOT_FOUND
}
