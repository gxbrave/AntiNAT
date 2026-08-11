//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	prSetNoNewPrivs = 38
	prGetNoNewPrivs = 39
	prSetSeccomp    = 22
	seccompFilter   = 2

	bpfLoadAbsolute = 0x20
	bpfJumpEqual    = 0x15
	bpfReturn       = 0x06

	seccompReturnKillProcess = 0x80000000
	seccompReturnErrno       = 0x00050000
	seccompReturnAllow       = 0x7fff0000
	auditArchX8664           = 0xc000003e
)

func Probe(executable string) Result {
	result := Result{Supported: true, Gates: make(map[string]GateResult)}
	if runtime.GOARCH != "amd64" {
		result.Supported = false
		result.Fallback = "webhook-only"
		result.Gates["seccomp_socket_connect"] = GateResult{Detail: "prototype seccomp program is amd64-only"}
		return result
	}
	if os.Geteuid() != 0 {
		result.Supported = false
		result.Fallback = "webhook-only"
		result.Gates["dedicated_uid"] = GateResult{Detail: "prototype requires root to create namespaces/chroot and drop to a dedicated UID"}
		return result
	}

	inspect := runAction(executable, "inspect")
	for _, name := range []string{"dedicated_uid", "no_new_privileges", "network_namespace", "mount_namespace_empty_root"} {
		result.Gates[name] = inspect
	}
	result.Gates["sanitized_env"] = runAction(executable, "env")
	result.Gates["no_inherited_fd"] = runAction(executable, "fd")
	result.Gates["seccomp_socket_connect"] = runAction(executable, "socket")
	result.Gates["seccomp_exec"] = runAction(executable, "exec")
	result.Gates["file_denied"] = runAction(executable, "file")
	result.Gates["cpu_bounded"] = runAction(executable, "loop")
	result.Gates["allocation_bounded"] = runAction(executable, "allocation")

	for _, gate := range result.Gates {
		if !gate.Pass {
			result.Supported = false
			result.Fallback = "webhook-only"
			break
		}
	}
	return result
}

func runAction(executable, action string) GateResult {
	root, err := os.MkdirTemp("", "antinat-sandbox-root-")
	if err != nil {
		return GateResult{Detail: err.Error()}
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o755); err != nil {
		return GateResult{Detail: err.Error()}
	}
	parentNetNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return GateResult{Detail: err.Error()}
	}
	parentMountNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return GateResult{Detail: err.Error()}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=TestSandboxChildHelper", "-test.v")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS}
	environment := []string{
		"PATH=/usr/bin:/bin",
		"ANTINAT_SANDBOX_HELPER=1",
		"ANTINAT_SANDBOX_ACTION=" + action,
		"ANTINAT_SANDBOX_ROOT=" + root,
		"ANTINAT_PARENT_NETNS=" + parentNetNS,
		"ANTINAT_PARENT_MNTNS=" + parentMountNS,
	}
	var sentinel *os.File
	if action == "fd" {
		sentinel, err = os.CreateTemp("", "antinat-sandbox-fd-")
		if err != nil {
			return GateResult{Detail: err.Error()}
		}
		defer func() {
			name := sentinel.Name()
			sentinel.Close()
			os.Remove(name)
		}()
		environment = append(environment, "ANTINAT_SENTINEL_FD="+strconv.Itoa(int(sentinel.Fd())))
	}
	cmd.Env = environment
	output, err := cmd.CombinedOutput()
	detail := strings.TrimSpace(string(output))
	if len(detail) > 500 {
		detail = detail[len(detail)-500:]
	}
	if action == "loop" || action == "allocation" {
		if err == nil {
			return GateResult{Detail: action + " unexpectedly completed"}
		}
		if ctx.Err() == context.DeadlineExceeded {
			return GateResult{Pass: true, Detail: action + " terminated by the 5s outer deadline"}
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return GateResult{Pass: true, Detail: action + " terminated by resource limit: " + detail}
		}
		return GateResult{Detail: fmt.Sprintf("%s failed unexpectedly: %v: %s", action, err, detail)}
	}
	if err != nil {
		return GateResult{Detail: fmt.Sprintf("%s: %v: %s", action, err, detail)}
	}
	return GateResult{Pass: true, Detail: detail}
}

func RunSandboxChild(action, root, parentNetNS, parentMountNS string) error {
	childNetNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	childMountNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return err
	}
	if childNetNS == parentNetNS {
		return errors.New("network namespace was not isolated")
	}
	if childMountNS == parentMountNS {
		return errors.New("mount namespace was not isolated")
	}
	if action == "loop" {
		if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: 1, Max: 1}); err != nil {
			return err
		}
	}
	if action == "allocation" {
		if err := limitAddressSpace(); err != nil {
			return err
		}
	}
	if err := syscall.Chroot(root); err != nil {
		return err
	}
	if err := os.Chdir("/"); err != nil {
		return err
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		return err
	}
	if err := syscall.Setgid(65534); err != nil {
		return err
	}
	if err := syscall.Setuid(65534); err != nil {
		return err
	}
	if err := setNoNewPrivileges(); err != nil {
		return err
	}
	if err := installSeccomp(); err != nil {
		return err
	}
	if os.Geteuid() != 65534 {
		return fmt.Errorf("effective UID = %d, want 65534", os.Geteuid())
	}

	switch action {
	case "inspect":
		return nil
	case "env":
		if value := os.Getenv("ANTINAT_SANDBOX_SECRET"); value != "" {
			return errors.New("secret environment variable leaked")
		}
		return nil
	case "fd":
		fd, err := strconv.Atoi(os.Getenv("ANTINAT_SENTINEL_FD"))
		if err != nil {
			return err
		}
		var stat syscall.Stat_t
		if err := syscall.Fstat(fd, &stat); !errors.Is(err, syscall.EBADF) {
			return fmt.Errorf("parent FD %d remained open: %v", fd, err)
		}
		return nil
	case "socket":
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err == nil {
			syscall.Close(fd)
			return errors.New("socket syscall unexpectedly succeeded")
		}
		if !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("socket error = %v, want EPERM", err)
		}
		if _, err := net.DialTimeout("tcp", "127.0.0.1:1", time.Millisecond); err == nil {
			return errors.New("connect unexpectedly succeeded")
		}
		return nil
	case "exec":
		err := syscall.Exec("/bin/sh", []string{"sh", "-c", "true"}, []string{})
		if !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("exec error = %v, want EPERM", err)
		}
		return nil
	case "file":
		if _, err := os.ReadFile("/etc/passwd"); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read /etc/passwd error = %v, want not-exist in empty root", err)
		}
		return nil
	case "loop":
		for {
		}
	case "allocation":
		memory := make([]byte, 512<<20)
		for index := 0; index < len(memory); index += os.Getpagesize() {
			memory[index] = 1
		}
		return errors.New("allocation unexpectedly succeeded")
	default:
		return fmt.Errorf("unknown malicious action %q", action)
	}
}

func setNoNewPrivileges() error {
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	value, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prGetNoNewPrivs, 0, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	if value != 1 {
		return fmt.Errorf("NoNewPrivileges = %d, want 1", value)
	}
	return nil
}

func installSeccomp() error {
	denied := []uintptr{
		syscall.SYS_SOCKET,
		syscall.SYS_SOCKETPAIR,
		syscall.SYS_CONNECT,
		syscall.SYS_EXECVE,
		322, // execveat on linux/amd64
		syscall.SYS_PTRACE,
		syscall.SYS_MOUNT,
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
		syscall.SYS_PRCTL,
		prSetSeccomp,
		seccompFilter,
		uintptr(unsafe.Pointer(&program)),
		0,
		0,
		0,
	); errno != 0 {
		return errno
	}
	return nil
}

func limitAddressSpace() error {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return errors.New("empty /proc/self/statm")
	}
	pages, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return err
	}
	limit := pages*uint64(os.Getpagesize()) + 64<<20
	return syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{Cur: limit, Max: limit})
}
