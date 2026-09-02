//go:build linux

package hook

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	"github.com/gxbrave/AntiNAT/internal/protocol"
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

	rlimitNPROC = 6 // RLIMIT_NPROC (6) on linux/amd64
)

const sandboxMaxOutput = 64 * 1024

func probeSandboxPlatform(executable string) SandboxResult {
	res := SandboxResult{Supported: true, Gates: map[string]GateResult{}}
	if runtime.GOARCH != "amd64" {
		return unsupportedSandbox("sandbox seccomp program is amd64-only")
	}
	if os.Geteuid() != 0 {
		return unsupportedSandbox("sandbox requires root to create namespaces/chroot and drop to a dedicated UID")
	}
	uid, gid, identityErr := dedicatedIdentity()
	if identityErr != nil {
		res.Gates["dedicated_uid"] = GateResult{Detail: "dedicated identity required: " + identityErr.Error()}
	} else {
		inspect := runAction(executable, "inspect")
		res.Gates["dedicated_uid"] = inspect
		if inspect.Pass {
			res.Gates["dedicated_uid"] = GateResult{
				Pass:   true,
				Detail: inspect.Detail + "; dropped to dedicated service UID " + strconv.Itoa(uid) + " GID " + strconv.Itoa(gid),
			}
		}
	}
	for _, name := range []string{"no_new_privileges", "network_namespace", "mount_namespace_empty_root"} {
		res.Gates[name] = runAction(executable, "inspect")
	}
	res.Gates["sanitized_env"] = runAction(executable, "env")
	res.Gates["no_inherited_fd"] = runAction(executable, "fd")
	res.Gates["seccomp_socket_connect"] = runAction(executable, "socket")
	res.Gates["seccomp_exec"] = runAction(executable, "exec")
	res.Gates["file_denied"] = runAction(executable, "file")
	res.Gates["cpu_bounded"] = runAction(executable, "loop")
	res.Gates["allocation_bounded"] = runAction(executable, "allocation")
	for _, gate := range res.Gates {
		if !gate.Pass {
			res.Supported = false
			res.Fallback = "webhook-only"
			break
		}
	}
	return res
}

// dedicatedIdentity resolves the provisioned service identity from
// ANTINAT_DEDICATED_UID / ANTINAT_DEDICATED_GID and fails closed unless it is a
// unique, non-shared account (the shared nobody/nogroup 65534 is rejected).
func dedicatedIdentity() (uid, gid int, err error) {
	uidText := os.Getenv("ANTINAT_DEDICATED_UID")
	gidText := os.Getenv("ANTINAT_DEDICATED_GID")
	if uidText == "" || gidText == "" {
		return 0, 0, errors.New("ANTINAT_DEDICATED_UID and ANTINAT_DEDICATED_GID must name a provisioned unique service identity")
	}
	uid, err = strconv.Atoi(uidText)
	if err != nil || uid <= 0 {
		return 0, 0, fmt.Errorf("invalid dedicated UID %q", uidText)
	}
	gid, err = strconv.Atoi(gidText)
	if err != nil || gid <= 0 {
		return 0, 0, fmt.Errorf("invalid dedicated GID %q", gidText)
	}
	if uid == 65534 || gid == 65534 {
		return 0, 0, errors.New("UID/GID 65534 is the shared nobody/nogroup identity, not a dedicated service identity")
	}
	passwdName, passwdCount, err := lookupPasswd(uid)
	if err != nil {
		return 0, 0, err
	}
	if passwdCount != 1 {
		return 0, 0, fmt.Errorf("UID %d appears in %d passwd entries; a dedicated service UID must be unique", uid, passwdCount)
	}
	if passwdName == "" || passwdName == "nobody" {
		return 0, 0, fmt.Errorf("UID %d maps to account %q, which is not a dedicated service account", uid, passwdName)
	}
	groupName, groupCount, err := lookupGroup(gid)
	if err != nil {
		return 0, 0, err
	}
	if groupCount != 1 {
		return 0, 0, fmt.Errorf("GID %d appears in %d group entries; a dedicated service GID must be unique", gid, groupCount)
	}
	if groupName == "" || groupName == "nogroup" {
		return 0, 0, fmt.Errorf("GID %d maps to group %q, which is not a dedicated service group", gid, groupName)
	}
	return uid, gid, nil
}

func lookupPasswd(uid int) (name string, count int, err error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		entryUID, parseErr := strconv.Atoi(fields[2])
		if parseErr != nil {
			continue
		}
		if entryUID == uid {
			count++
			name = fields[0]
		}
	}
	if err := scanner.Err(); err != nil {
		return "", 0, err
	}
	if count == 0 {
		return "", 0, fmt.Errorf("UID %d has no /etc/passwd entry", uid)
	}
	return name, count, nil
}

func lookupGroup(gid int) (name string, count int, err error) {
	file, err := os.Open("/etc/group")
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		entryGID, parseErr := strconv.Atoi(fields[2])
		if parseErr != nil {
			continue
		}
		if entryGID == gid {
			count++
			name = fields[0]
		}
	}
	if err := scanner.Err(); err != nil {
		return "", 0, err
	}
	if count == 0 {
		return "", 0, fmt.Errorf("GID %d has no /etc/group entry", gid)
	}
	return name, count, nil
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
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-selfcheck", action)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS, Setpgid: true}
	cmd.Env = sandboxEnv(root, parentNetNS, parentMountNS)
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
		cmd.Env = append(cmd.Env, "ANTINAT_SENTINEL_FD="+strconv.Itoa(int(sentinel.Fd())))
	}
	output := &cappedWriter{max: sandboxMaxOutput}
	cmd.Stdout = output
	cmd.Stderr = output
	startErr := cmd.Start()
	if startErr != nil {
		return GateResult{Detail: startErr.Error()}
	}
	waitErr := cmd.Wait()
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	fullDetail := strings.TrimSpace(output.String())
	detail := fullDetail
	if output.capped {
		detail = "[[output truncated at " + strconv.Itoa(sandboxMaxOutput) + " bytes]] " + detail
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
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				if pass, reason := boundedActionPassed(action, ctx.Err(), status, fullDetail); pass {
					return GateResult{Pass: true, Detail: reason + ": " + detail}
				}
			}
		}
		return GateResult{Detail: fmt.Sprintf("%s failed unexpectedly: %v: %s", action, waitErr, detail)}
	}
	if waitErr != nil {
		return GateResult{Detail: fmt.Sprintf("%s: %v: %s", action, waitErr, detail)}
	}
	return GateResult{Pass: true, Detail: detail}
}

func sandboxEnv(root, parentNetNS, parentMountNS string) []string {
	return []string{
		"PATH=/usr/bin:/bin",
		"GOMAXPROCS=2",
		"ANTINAT_SANDBOX_HELPER=1",
		"ANTINAT_SANDBOX_ROOT=" + root,
		"ANTINAT_PARENT_NETNS=" + parentNetNS,
		"ANTINAT_PARENT_MNTNS=" + parentMountNS,
		"ANTINAT_DEDICATED_UID=" + os.Getenv("ANTINAT_DEDICATED_UID"),
		"ANTINAT_DEDICATED_GID=" + os.Getenv("ANTINAT_DEDICATED_GID"),
	}
}

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
		if status.Signaled() && status.Signal() == syscall.SIGXCPU {
			return true, "loop terminated by the configured RLIMIT_CPU soft limit (SIGXCPU)"
		}
		lower := strings.ToLower(output)
		if status.ExitStatus() == 42 && strings.Contains(lower, "sigxcpu") {
			return true, "loop observed the configured RLIMIT_CPU soft limit (SIGXCPU) and exited"
		}
	case "allocation":
		lower := strings.ToLower(output)
		if strings.Contains(lower, "out of memory") || strings.Contains(lower, "cannot allocate memory") {
			return true, "allocation terminated after the address-space limit"
		}
	}
	return false, "termination did not prove the configured resource bound"
}

// runSandboxedScript runs the antinat-hook-runner child in sandboxed run mode
// with the script+request envelope on stdin and returns the bounded output.
func runSandboxedScript(ctx context.Context, executable string, script, request []byte, limits Limits) ([]byte, error) {
	root, err := os.MkdirTemp("", "antinat-sandbox-root-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o755); err != nil {
		return nil, err
	}
	parentNetNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	parentMountNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return nil, err
	}
	envelope, err := json.Marshal(map[string]any{
		"script_sha256": sha256HexOfString(string(script)),
		"script":        string(script),
		"request":       string(request),
		"max_ms":        int(limits.Timeout.Milliseconds()),
		"max_steps":     limits.MaxSteps,
		"max_output":    limits.MaxOutputBytes,
	})
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, executable, "-selfcheck", "run")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS, Setpgid: true}
	cmd.Env = sandboxEnv(root, parentNetNS, parentMountNS)
	cmd.Stdin = strings.NewReader(string(envelope))
	output := &cappedWriter{max: sandboxMaxOutput}
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	waitErr := cmd.Wait()
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if waitErr != nil {
		detail := strings.TrimSpace(output.String())
		if len(detail) > 400 {
			detail = detail[len(detail)-400:]
		}
		return nil, fmt.Errorf("hook: sandbox runner exited: %v: %s", waitErr, detail)
	}
	return []byte(output.String()), nil
}

// ChildSandboxSetup runs inside the sandboxed child: verifies namespace
// isolation, resolves+validates the dedicated identity, chroots to the empty
// root, drops privileges, sets NoNewPrivileges, installs the seccomp filter
// and applies the resource limits. It must run before any action.
func ChildSandboxSetup(action string, uid, gid int) error {
	childNetNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	childMountNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return err
	}
	if childNetNS == os.Getenv("ANTINAT_PARENT_NETNS") {
		return errors.New("network namespace was not isolated")
	}
	if childMountNS == os.Getenv("ANTINAT_PARENT_MNTNS") {
		return errors.New("mount namespace was not isolated")
	}
	if action == "loop" {
		if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: 1, Max: 2}); err != nil {
			return err
		}
	}
	if action == "allocation" {
		if err := limitAddressSpace(); err != nil {
			return err
		}
	}
	if action == "run" {
		// Bounded best-effort run backstops: NPROC, AS and CPU soft cap.
		if err := syscall.Setrlimit(rlimitNPROC, &syscall.Rlimit{Cur: 32, Max: 32}); err != nil {
			return err
		}
		if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: 10, Max: 30}); err != nil {
			return err
		}
		if err := limitAddressSpace(); err != nil {
			return err
		}
	} else {
		if err := syscall.Setrlimit(rlimitNPROC, &syscall.Rlimit{Cur: 16, Max: 16}); err != nil {
			return err
		}
	}
	if err := syscall.Chroot(os.Getenv("ANTINAT_SANDBOX_ROOT")); err != nil {
		return fmt.Errorf("chroot: %w", err)
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
	return nil
}

// ChildEntry is the antinat-hook-runner entrypoint: resolve the dedicated
// identity (before the chroot hides /etc/passwd), then run the action inside
// the sandbox.
func ChildEntry(action string) error {
	uid, gid, err := dedicatedIdentity()
	if err != nil {
		return err
	}
	return ChildSelfCheck(action, uid, gid)
}

// ChildSelfCheck executes a gate/run action after ChildSandboxSetup. It is
// called by cmd/antinat-hook-runner inside the sandbox.
func ChildSelfCheck(action string, uid, gid int) error {
	if err := ChildSandboxSetup(action, uid, gid); err != nil {
		return err
	}
	switch action {
	case "run":
		return childRunScript()
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

func childRunScript() error {
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 128<<10))
	if err != nil {
		return err
	}
	var envelope struct {
		ScriptSHA256 string `json:"script_sha256"`
		Script       string `json:"script"`
		Request      string `json:"request"`
		MaxMS        int    `json:"max_ms"`
		MaxSteps     int    `json:"max_steps"`
		MaxOutput    int    `json:"max_output"`
	}
	if err := protocol.DecodeStrictJSONInto(input, &envelope); err != nil {
		return err
	}
	limits := DefaultLimits()
	if envelope.MaxMS > 0 {
		limits.Timeout = time.Duration(envelope.MaxMS) * time.Millisecond
	}
	if envelope.MaxSteps > 0 {
		limits.MaxSteps = envelope.MaxSteps
	}
	if envelope.MaxOutput > 0 {
		limits.MaxOutputBytes = envelope.MaxOutput
	}
	runner := NewRunner(limits)
	result, err := runner.Run(context.Background(), Input{
		ScriptSHA256: envelope.ScriptSHA256,
		Script:       envelope.Script,
		Request:      []byte(envelope.Request),
	})
	if err != nil {
		return err
	}
	// The parent sees a bounded envelope; Results exceeding the OS stdout cap
	// would be truncated by the parent's capped reader, so keep it compact.
	out, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
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
