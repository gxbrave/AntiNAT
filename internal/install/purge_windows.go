//go:build windows

package install

import (
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
		windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_SYNCHRONOUS_IO_NONALERT|options,
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
