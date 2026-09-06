//go:build linux && amd64

package hook

import (
	"syscall"
	"unsafe"
)

const (
	bpfLoadAbsolute = 0x20
	bpfJumpEqual    = 0x15
	bpfReturn       = 0x06

	seccompReturnKillProcess = 0x80000000
	seccompReturnErrno       = 0x00050000
	seccompReturnAllow       = 0x7fff0000
	auditArchX8664           = 0xc000003e
)

func installSeccomp() error {
	denied := []uintptr{
		syscall.SYS_SOCKET,
		syscall.SYS_SOCKETPAIR,
		syscall.SYS_CONNECT,
		syscall.SYS_EXECVE,
		322, // execveat on linux/amd64
		syscall.SYS_PTRACE,
		syscall.SYS_MOUNT,
		syscall.SYS_FORK,
		syscall.SYS_VFORK,
	}
	filters := []syscall.SockFilter{
		{Code: bpfLoadAbsolute, K: 4},
		{Code: bpfJumpEqual, Jt: 1, Jf: 0, K: auditArchX8664},
		{Code: bpfReturn, K: seccompReturnKillProcess},
		{Code: bpfLoadAbsolute, K: 0},
	}
	for _, systemCall := range denied {
		filters = append(filters,
			syscall.SockFilter{Code: bpfJumpEqual, Jt: 0, Jf: 1, K: uint32(systemCall)},
			syscall.SockFilter{Code: bpfReturn, K: seccompReturnErrno | uint32(syscall.EPERM)},
		)
	}
	filters = append(filters, syscall.SockFilter{Code: bpfReturn, K: seccompReturnAllow})
	program := syscall.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	if _, _, errno := syscall.RawSyscall6(
		syscall.SYS_PRCTL, prSetSeccomp, seccompFilter, uintptr(unsafe.Pointer(&program)), 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
