//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
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

	// rlimitNPROC is RLIMIT_NPROC (6) on linux/amd64; the syscall package does
	// not expose it, so the prototype defines the constant for this target.
	rlimitNPROC = 6
)

func Probe(executable string) Result {
	result := Result{Supported: true, Gates: make(map[string]GateResult)}
	if runtime.GOARCH != "amd64" {
		return unsupportedResult("prototype seccomp program is amd64-only")
	}
	if os.Geteuid() != 0 {
		return unsupportedResult("prototype requires root to create namespaces/chroot and drop to a dedicated UID")
	}

	// The dedicated-identity minimum gate: a provisioned, unique, non-nobody
	// service UID/GID must be supplied. A shared nobody/nogroup identity or a
	// missing provision is a failed gate, not a PASS.
	uid, gid, identityErr := dedicatedIdentity()
	if identityErr != nil {
		result.Gates["dedicated_uid"] = GateResult{Detail: "dedicated identity required: " + identityErr.Error()}
	} else {
		inspect := runAction(executable, "inspect")
		result.Gates["dedicated_uid"] = inspect
		if inspect.Pass {
			result.Gates["dedicated_uid"] = GateResult{
				Pass:   true,
				Detail: inspect.Detail + "; dropped to dedicated service UID " + strconv.Itoa(uid) + " GID " + strconv.Itoa(gid),
			}
		}
	}
	for _, name := range []string{"no_new_privileges", "network_namespace", "mount_namespace_empty_root"} {
		result.Gates[name] = runAction(executable, "inspect")
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
	// Setpgid places the child (and any descendants it manages to create) in a
	// private process group so the parent can contain and kill the whole tree
	// after termination, not just the direct child.
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS, Setpgid: true}
	environment := []string{
		"PATH=/usr/bin:/bin",
		"ANTINAT_SANDBOX_HELPER=1",
		"ANTINAT_SANDBOX_ACTION=" + action,
		"ANTINAT_SANDBOX_ROOT=" + root,
		"ANTINAT_PARENT_NETNS=" + parentNetNS,
		"ANTINAT_PARENT_MNTNS=" + parentMountNS,
		"ANTINAT_DEDICATED_UID=" + os.Getenv("ANTINAT_DEDICATED_UID"),
		"ANTINAT_DEDICATED_GID=" + os.Getenv("ANTINAT_DEDICATED_GID"),
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
	// Stream the child output through a bounded writer so an unbounded
	// malicious stdout/stderr cannot exhaust the parent's memory before the
	// displayed detail is truncated.
	output := &cappedWriter{max: maxActionOutput}
	cmd.Stdout = output
	cmd.Stderr = output
	startErr := cmd.Start()
	if startErr != nil {
		return GateResult{Detail: startErr.Error()}
	}
	waitErr := cmd.Wait()
	// Contain descendants: kill any surviving member of the child's process
	// group, including processes forked/cloned by the fixture after the direct
	// child was reaped or timed out.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	fullDetail := strings.TrimSpace(output.String())
	detail := fullDetail
	if output.capped {
		detail = "[[output truncated at " + strconv.Itoa(maxActionOutput) + " bytes]] " + detail
	}
	if len(detail) > 500 {
		detail = detail[len(detail)-500:]
	}
	if action == "loop" || action == "allocation" {
		if waitErr == nil {
			return GateResult{Detail: action + " unexpectedly completed"}
		}
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			status, ok := exitErr.Sys().(syscall.WaitStatus)
			if !ok {
				return GateResult{Detail: action + " returned a non-Unix wait status"}
			}
			if pass, reason := boundedActionPassed(action, ctx.Err(), status, fullDetail); pass {
				return GateResult{Pass: true, Detail: reason + ": " + detail}
			}
		}
		return GateResult{Detail: fmt.Sprintf("%s failed unexpectedly: %v: %s", action, waitErr, detail)}
	}
	if waitErr != nil {
		return GateResult{Detail: fmt.Sprintf("%s: %v: %s", action, waitErr, detail)}
	}
	return GateResult{Pass: true, Detail: detail}
}

// maxActionOutput caps how much child stdout/stderr the parent will buffer.
const maxActionOutput = 64 * 1024

// cappedWriter discards bytes beyond max while remembering that truncation
// happened, so the parent memory use is bounded even for hostile output.
type cappedWriter struct {
	buf    []byte
	max    int
	capped bool
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if len(w.buf) >= w.max {
		w.capped = true
		return len(p), nil
	}
	remaining := w.max - len(w.buf)
	if len(p) > remaining {
		w.buf = append(w.buf, p[:remaining]...)
		w.capped = true
	} else {
		w.buf = append(w.buf, p...)
	}
	return len(p), nil
}

func (w *cappedWriter) String() string { return string(w.buf) }

func boundedActionPassed(action string, contextErr error, status syscall.WaitStatus, output string) (bool, string) {
	if contextErr == context.DeadlineExceeded {
		return false, "outer deadline expired before a proven resource-limit termination"
	}
	switch action {
	case "loop":
		// The configured soft RLIMIT_CPU is proven only by limit-specific
		// observables: a kernel-default SIGXCPU wait status, or the child's
		// on-stdout SIGXCPU marker with its distinctive exit code. A generic
		// SIGKILL (OOM killer, external kill, seccomp kill, unrelated
		// supervisor) is not limit-specific evidence and fails closed.
		if status.Signaled() && status.Signal() == syscall.SIGXCPU {
			return true, "loop terminated by the configured RLIMIT_CPU soft limit (SIGXCPU)"
		}
		lower := strings.ToLower(output)
		if status.ExitStatus() == 42 && strings.Contains(lower, "sigxcpu") {
			return true, "loop observed the configured RLIMIT_CPU soft limit (SIGXCPU) and exited"
		}
	case "allocation":
		// The address-space limit is proven only by the runtime's observable
		// out-of-memory message; an arbitrary fatal exit or signal is not.
		lower := strings.ToLower(output)
		if strings.Contains(lower, "out of memory") || strings.Contains(lower, "cannot allocate memory") {
			return true, "allocation terminated after the address-space limit"
		}
	}
	return false, "termination did not prove the configured resource bound"
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
	// Resolve the provisioned dedicated identity before the chroot hides
	// /etc/passwd and /etc/group.
	uid, gid, err := dedicatedIdentity()
	if err != nil {
		return err
	}
	if action == "loop" {
		// Soft limit 1s fires SIGXCPU (the observable, limit-specific proof);
		// hard limit 2s is the backstop SIGKILL only if the fixture survived
		// the soft limit.
		if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: 1, Max: 2}); err != nil {
			return err
		}
	}
	if action == "allocation" {
		if err := limitAddressSpace(); err != nil {
			return err
		}
	}
	// Bound the number of processes/threads this identity may create so a
	// malicious fixture cannot multiply descendants to exhaust the host.
	if err := syscall.Setrlimit(rlimitNPROC, &syscall.Rlimit{Cur: 16, Max: 16}); err != nil {
		return err
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
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	if err := syscall.Setuid(uid); err != nil {
		return err
	}
	if err := setNoNewPrivileges(); err != nil {
		return err
	}
	if err := installSeccomp(); err != nil {
		return err
	}
	if os.Geteuid() != uid || os.Getegid() != gid {
		return fmt.Errorf("effective identity = %d/%d, want %d/%d", os.Geteuid(), os.Getegid(), uid, gid)
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
		// SIGXCPU is generated only by RLIMIT_CPU on Linux. The Go runtime
		// otherwise swallows the soft-limit signal (dying only at the hard
		// limit with a generic SIGKILL), so the child observes the configured
		// soft-limit SIGXCPU and exits with a distinctive code plus an
		// on-stdout marker. The parent requires that observable marker, so an
		// unrelated OOM/external/seccomp kill can never masquerade as a
		// CPU-limit PASS.
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGXCPU)
		go func() {
			<-sigc
			fmt.Println("sandbox: received SIGXCPU from the configured RLIMIT_CPU soft limit")
			os.Exit(42)
		}()
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
		// fork/vfork are denied so a fixture cannot multiply into new
		// processes; clone/clone3 remain available only because the Go
		// runtime may need new threads, and are bounded by RLIMIT_NPROC plus
		// the parent's process-group kill.
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
