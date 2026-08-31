//go:build linux && netns

// P13 UDP single-socket data-plane lab (Story 6): drives the production UDP
// forwarder (internal/forward/udp) inside a three-namespace topology
// (agent/CPE/vantage) against real cross-namespace UDP echo targets, with an
// independent external client, exact-source ingress replies, the production
// strict probe classifier (reconcile.ProbeManager over a real localstate
// store and node key, exactly as the agent's composition root wires it),
// target hot update, idle expiry, session-cap rejection, oversized/truncated
// handling, and P12-style signal/cleanup lifecycle.
//
// Run: go test -tags=netns ./test/integration -run TestUDP -count=1 -v
package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT/internal/forward"
	udpforward "github.com/gxbrave/AntiNAT/internal/forward/udp"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/security"
	"github.com/gxbrave/AntiNAT/internal/traversal"
)

// lab coordinates are parsed from test/netns/udp_lab.sh.
type udpLab struct {
	t         *testing.T
	prefix    string
	script    string
	agentNS   string
	cpeNS     string
	vantageNS string
	agentIP   string
	gateway   string
	cpeWAN    string
	vantageIP string
	echoA     string
	echoB     string
	workDir   string
	echoAPID  string
	echoBPID  string
	client    string // workDir/udp_client.py
}

func requireUDPLabPrerequisites(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("netns lab requires root; run with sudo -E")
	}
	for _, command := range []string{"ip", "nft", "python3", "bash"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("netns lab prerequisite %s unavailable: %v", command, err)
		}
	}
}

// TestUDPLabSignalCleanup pins keep-mode interrupt handling: a SIGTERM
// delivered after every namespace and daemon exists must make the EXIT trap
// tear the whole topology down instead of publishing READY=1 or leaking.
func TestUDPLabSignalCleanup(t *testing.T) {
	requireUDPLabPrerequisites(t)
	script, err := filepath.Abs(filepath.Join("..", "netns", "udp_lab.sh"))
	if err != nil {
		t.Fatalf("locate lab script: %v", err)
	}
	prefix := fmt.Sprintf("antinat-p13-signal-%d", os.Getpid())
	holdFile := filepath.Join(t.TempDir(), "ready-hold")
	cmd := exec.Command("bash", script)
	cmd.Env = append(os.Environ(),
		"ANTINAT_P13_KEEP=1",
		"ANTINAT_P13_PREFIX="+prefix,
		"ANTINAT_P13_READY_HOLD_FILE="+holdFile,
	)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start held lab setup: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(holdFile); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(holdFile); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("lab never reached the signal hold: %v\n%s", err, output.String())
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal held lab: %v", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("SIGTERM setup must return a nonzero interrupted status")
	}
	if strings.Contains(output.String(), "READY=1") {
		t.Fatalf("interrupted setup published READY=1:\n%s", output.String())
	}
	namespaces, _ := exec.Command("ip", "netns", "list").CombinedOutput()
	if strings.Contains(string(namespaces), prefix) {
		t.Fatalf("signal-interrupted setup leaked namespaces:\n%s", namespaces)
	}
	procs, _ := exec.Command("pgrep", "-af", "udp_echo.py").CombinedOutput()
	if strings.Contains(string(procs), prefix) {
		t.Fatalf("signal-interrupted setup leaked echo daemons:\n%s", procs)
	}
}

// startLab creates a live topology in keep mode and registers teardown.
func startUDPLab(t *testing.T) *udpLab {
	t.Helper()
	script, err := filepath.Abs(filepath.Join("..", "netns", "udp_lab.sh"))
	if err != nil {
		t.Fatalf("locate lab script: %v", err)
	}
	prefix := fmt.Sprintf("antinat-p13-t%d", os.Getpid())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", script)
	cmd.Env = append(os.Environ(),
		"ANTINAT_P13_KEEP=1",
		"ANTINAT_P13_PREFIX="+prefix,
	)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("lab script timed out:\n%s", output)
	}
	if err != nil {
		t.Fatalf("lab script failed: %v\n%s", err, output)
	}

	l := &udpLab{t: t, prefix: prefix, script: script}
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "AGENT":
			l.agentIP = value
		case "GATEWAY":
			l.gateway = value
		case "CPE_WAN":
			l.cpeWAN = value
		case "VANTAGE":
			l.vantageIP = value
		case "ECHO_A":
			l.echoA = value
		case "ECHO_B":
			l.echoB = value
		case "AGENT_NS":
			l.agentNS = value
		case "CPE_NS":
			l.cpeNS = value
		case "VANTAGE_NS":
			l.vantageNS = value
		case "WORK_DIR":
			l.workDir = value
		case "ECHO_A_PID":
			l.echoAPID = value
		case "ECHO_B_PID":
			l.echoBPID = value
		}
	}
	if l.agentIP == "" || l.echoA == "" || l.echoB == "" || l.agentNS == "" || l.workDir == "" {
		t.Fatalf("lab script output missing topology markers:\n%s", output)
	}
	l.client = filepath.Join(l.workDir, "udp_client.py")
	t.Logf("lab topology: agent=%s echo_a=%s echo_b=%s cpe_wan=%s vantage=%s",
		l.agentIP, l.echoA, l.echoB, l.cpeWAN, l.vantageIP)
	t.Cleanup(l.teardown)
	return l
}

// teardown runs the lab script in teardown mode and asserts zero residue:
// no namespaces, no echo daemons and no work dir may survive. Each residue
// check fails the owning test so a leak is caught and enforced, not only logged.
func (l *udpLab) teardown() {
	cmd := exec.Command("bash", l.script)
	cmd.Env = append(os.Environ(),
		"ANTINAT_P13_TEARDOWN=1",
		"ANTINAT_P13_PREFIX="+l.prefix,
		"ANTINAT_P13_WORK_DIR="+l.workDir,
		"ANTINAT_P13_ECHO_A_PID="+l.echoAPID,
		"ANTINAT_P13_ECHO_B_PID="+l.echoBPID,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		l.t.Errorf("lab teardown failed: %v\n%s", err, output)
	}
	namespaces, _ := exec.Command("ip", "netns", "list").CombinedOutput()
	if strings.Contains(string(namespaces), l.prefix) {
		l.t.Errorf("lab namespace leaked after cleanup:\n%s", namespaces)
	}
	procs, _ := exec.Command("pgrep", "-af", "udp_echo.py").CombinedOutput()
	if strings.Contains(string(procs), l.workDir) {
		l.t.Errorf("lab echo daemon leaked after cleanup:\n%s", procs)
	}
	if _, err := os.Stat(l.workDir); err == nil {
		l.t.Errorf("lab work dir leaked after cleanup: %s", l.workDir)
	}
}

// ---------------------------------------------------------------------------
// results-file protocol (child -> parent)
// ---------------------------------------------------------------------------

// readEvents parses every complete JSON line of the child results file.
func readEvents(path string) []map[string]any {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var events []map[string]any
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev map[string]any
		if json.Unmarshal([]byte(line), &ev) == nil && ev["event"] != nil {
			events = append(events, ev)
		}
	}
	return events
}

func waitEvent(t *testing.T, path, name string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range readEvents(path) {
			if ev["event"] == name {
				return ev
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	raw, _ := os.ReadFile(path)
	t.Fatalf("child never reported event %q; results:\n%s", name, raw)
	return nil
}

// waitStats polls the latest child stats line until pred holds.
func waitStats(t *testing.T, path string, pred func(ev map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		var latest map[string]any
		for _, ev := range readEvents(path) {
			if ev["event"] == "stats" {
				latest = ev
			}
		}
		if latest != nil && pred(latest) {
			return latest
		}
		time.Sleep(50 * time.Millisecond)
	}
	raw, _ := os.ReadFile(path)
	t.Fatalf("child stats never satisfied predicate; results:\n%s", raw)
	return nil
}

func waitStatsActive(t *testing.T, path string, want int) {
	t.Helper()
	waitStats(t, path, func(ev map[string]any) bool {
		active, _ := ev["active"].(float64)
		return int(active) == want
	})
}

// writeCmd appends one command line for the child.
func writeCmd(t *testing.T, path, command string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open cmd file: %v", err)
	}
	if _, err := f.WriteString(command + "\n"); err != nil {
		f.Close()
		t.Fatalf("write cmd file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close cmd file: %v", err)
	}
}

// ---------------------------------------------------------------------------
// vantage client (external side)
// ---------------------------------------------------------------------------

type sendResult struct {
	resp []byte
	from string
	got  bool
}

// vantageSend sends one datagram from a vantage socket bound to bindPort
// (0 lets the kernel pick) and returns the response payload and its exact
// source tuple ("" when no response arrives). A fixed bind port expresses a
// distinct client tuple deterministically.
func (l *udpLab) vantageSend(t *testing.T, published string, bindPort int, payload []byte, timeout time.Duration) sendResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout+3*time.Second)
	defer cancel()
	args := []string{"python3", l.client}
	if bindPort > 0 {
		args = append(args, "--bind-port", strconv.Itoa(bindPort))
	}
	args = append(args, published, base64.StdEncoding.EncodeToString(payload),
		strconv.Itoa(int(timeout.Milliseconds())))
	cmdArgs := []string{"netns", "exec", l.vantageNS}
	cmdArgs = append(cmdArgs, args...)
	output, err := exec.CommandContext(ctx, "ip", cmdArgs...).CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("vantage client timed out:\n%s", output)
	}
	if err != nil {
		t.Fatalf("vantage client failed: %v\n%s", err, output)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if !strings.HasPrefix(line, "RESP=") {
			continue
		}
		rest := strings.TrimPrefix(line, "RESP=")
		parts := strings.SplitN(rest, " FROM=", 2)
		resp, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("decode vantage response: %v (%q)", err, line)
		}
		res := sendResult{resp: resp, got: true}
		if len(parts) == 2 {
			res.from = parts[1]
		}
		return res
	}
	return sendResult{}
}

// vantageExchange asserts a response arrives and matches the payload.
func (l *udpLab) vantageExchange(t *testing.T, published string, bindPort int, payload []byte, timeout time.Duration) sendResult {
	t.Helper()
	res := l.vantageSend(t, published, bindPort, payload, timeout)
	if !res.got {
		t.Fatalf("no response to %q (bind port %d)", payload, bindPort)
	}
	return res
}

// vantageBurst opens count fresh sockets bound to bindPort..bindPort+count-1,
// sends one datagram from each in quick succession and reports how many
// received a response.
func (l *udpLab) vantageBurst(t *testing.T, published string, bindPort, count int, payload []byte, timeout time.Duration) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout+3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ip", "netns", "exec", l.vantageNS,
		"python3", l.client, "--burst", "--bind-port", strconv.Itoa(bindPort), published,
		base64.StdEncoding.EncodeToString(payload), strconv.Itoa(count),
		strconv.Itoa(int(timeout.Milliseconds()))).CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("vantage burst timed out:\n%s", output)
	}
	if err != nil {
		t.Fatalf("vantage burst failed: %v\n%s", err, output)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "RESPONSES=") {
			n, err := strconv.Atoi(strings.TrimPrefix(line, "RESPONSES="))
			if err != nil {
				t.Fatalf("parse burst count %q: %v", line, err)
			}
			return n
		}
	}
	t.Fatalf("vantage burst printed no RESPONSES line:\n%s", output)
	return 0
}

// Distinct vantage client identities, each a fixed source port.
const (
	clientPort1 = 31001
	clientPort2 = 31002
	clientPort5 = 31005
	burstBase   = 31010
)

// ---------------------------------------------------------------------------
// TestUDP: external echo, hot update, exact source, expiry, session cap,
// oversized/truncated handling, probe strict demux, and cleanup.
// ---------------------------------------------------------------------------

func TestUDP(t *testing.T) {
	requireUDPLabPrerequisites(t)
	if os.Getenv("ANTINAT_LAB_MODE") != "" {
		return
	}
	labEnv := startUDPLab(t)

	resultsFile := filepath.Join(labEnv.workDir, "results.jsonl")
	cmdFile := filepath.Join(labEnv.workDir, "cmd.txt")
	wan1File := filepath.Join(labEnv.workDir, "wan1.bin")
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	child := exec.Command("ip", "netns", "exec", labEnv.agentNS, executable,
		"-test.run=TestUDPAgentChild", "-test.v", "-test.timeout=120s")
	child.Env = append(os.Environ(),
		"ANTINAT_LAB_MODE=agent",
		"ANTINAT_LAB_AGENT_IP="+labEnv.agentIP,
		"ANTINAT_LAB_CLIENT_IP="+labEnv.vantageIP,
		"ANTINAT_LAB_ECHO_A="+labEnv.echoA,
		"ANTINAT_LAB_ECHO_B="+labEnv.echoB,
		"ANTINAT_LAB_RESULTS="+resultsFile,
		"ANTINAT_LAB_CMD="+cmdFile,
		"ANTINAT_LAB_STATE_DIR="+filepath.Join(labEnv.workDir, "child-state"),
	)
	var childOutput bytes.Buffer
	child.Stdout = &childOutput
	child.Stderr = &childOutput
	if err := child.Start(); err != nil {
		t.Fatalf("start agent child: %v", err)
	}
	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()
	// A failed parent assertion must still let the child exit before the
	// namespace teardown.
	t.Cleanup(func() {
		_ = os.WriteFile(cmdFile, []byte("close\n"), 0o600)
		if child.ProcessState == nil {
			_ = child.Process.Kill()
		}
	})

	// The child publishes the forwarder's tuple and the armed probe once the
	// forwarder is running.
	deadline := time.Now().Add(30 * time.Second)
	var published string
	for time.Now().Before(deadline) {
		select {
		case err := <-childDone:
			t.Fatalf("agent child exited before readiness: %v\n%s", err, childOutput.String())
		default:
		}
		for _, ev := range readEvents(resultsFile) {
			if ev["event"] == "ready" {
				if p, ok := ev["published"].(string); ok && p != "" {
					published = p
				}
			}
		}
		if published != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if published == "" {
		t.Fatalf("agent child never published a ready tuple:\n%s", childOutput.String())
	}
	t.Logf("forwarder published tuple: %s", published)

	// S1: external UDP echo through the published tuple, with the exact
	// published source asserted on the reply.
	res := labEnv.vantageExchange(t, published, clientPort1, []byte("ping-1"), 2*time.Second)
	if string(res.resp) != "A:ping-1" {
		t.Fatalf("echo response = %q, want %q", res.resp, "A:ping-1")
	}
	if res.from != published {
		t.Fatalf("echo response source %s, want the published tuple %s", res.from, published)
	}

	// S2: target hot update — the existing client tuple keeps its old target
	// while a new client tuple resolves the new target (NEW_SESSIONS_ONLY).
	writeCmd(t, cmdFile, "target=b")
	waitEvent(t, resultsFile, "hotupdate")
	if res := labEnv.vantageExchange(t, published, clientPort1, []byte("ping-2"), 2*time.Second); string(res.resp) != "A:ping-2" {
		t.Fatalf("old tuple after hot update = %q, want it to keep target A", res.resp)
	}
	if res := labEnv.vantageExchange(t, published, clientPort2, []byte("ping-3"), 2*time.Second); string(res.resp) != "B:ping-3" {
		t.Fatalf("new tuple after hot update = %q, want target B", res.resp)
	}

	// S3: target close — the correlated error removes only the affected
	// session; the unrelated session and the ingress socket survive.
	pid, err := strconv.Atoi(labEnv.echoAPID)
	if err != nil {
		t.Fatalf("parse echo A pid: %v", err)
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatalf("kill echo target A: %v", err)
	}
	if res := labEnv.vantageSend(t, published, clientPort1, []byte("ping-4"), 800*time.Millisecond); res.got {
		t.Fatalf("session to the closed target still produced a reply: %q", res.resp)
	}
	waitStatsActive(t, resultsFile, 1) // only the A session is removed
	if res := labEnv.vantageExchange(t, published, clientPort2, []byte("ping-5"), 2*time.Second); string(res.resp) != "B:ping-5" {
		t.Fatalf("unrelated session after target close = %q, want target B", res.resp)
	}
	if res := labEnv.vantageExchange(t, published, clientPort1, []byte("ping-6"), 2*time.Second); string(res.resp) != "B:ping-6" {
		t.Fatalf("recovery after target close = %q, want target B", res.resp)
	}
	waitStatsActive(t, resultsFile, 2)

	// S4: idle expiry — the expirer drops every session and the next datagram
	// re-establishes one against the current backend.
	time.Sleep(2500 * time.Millisecond)
	waitStatsActive(t, resultsFile, 0)
	if res := labEnv.vantageExchange(t, published, clientPort1, []byte("ping-7"), 2*time.Second); string(res.resp) != "B:ping-7" {
		t.Fatalf("post-expiry echo = %q, want target B", res.resp)
	}

	// S6a: a large datagram near the bounded 65,507-byte pool round-trips
	// through the ingress and target, and a normal packet continues after it.
	big := make([]byte, 60000)
	copy(big, "BIG:")
	if res := labEnv.vantageExchange(t, published, clientPort5, big, 3*time.Second); !bytes.HasPrefix(res.resp, []byte("B:")) || len(res.resp) != len(big)+2 {
		t.Fatalf("large datagram echo len = %d (want %d), want B: prefix", len(res.resp), len(big)+2)
	}
	if res := labEnv.vantageExchange(t, published, clientPort5, []byte("ping-8"), 2*time.Second); string(res.resp) != "B:ping-8" {
		t.Fatalf("normal packet after oversized datagram = %q", res.resp)
	}

	// S6b: STUN-lookalike and truncated control frames never match the strict
	// classifier and reach the business path.
	lookalike := append([]byte{0x00, 0x01, 0x00, 0x00}, []byte("stun-lookalike")...)
	if res := labEnv.vantageExchange(t, published, clientPort5, lookalike, 2*time.Second); !bytes.Equal(res.resp, append([]byte("B:"), lookalike...)) {
		t.Fatalf("STUN-lookalike did not take the business path: %q", res.resp)
	}
	wan1, err := os.ReadFile(wan1File)
	if err != nil {
		t.Fatalf("read child WAN1 frame: %v", err)
	}
	truncated := append([]byte(nil), wan1[:30]...)
	if res := labEnv.vantageExchange(t, published, clientPort5, truncated, 2*time.Second); !bytes.Equal(res.resp, append([]byte("B:"), truncated...)) {
		t.Fatalf("truncated control frame did not fall through to business: %q", res.resp)
	}

	// S6c: a full-match signed WAN1 for the armed probe is consumed at the
	// control path: ACK1 returns from the published tuple and the frame is
	// never forwarded to the business target.
	wan1Result := labEnv.vantageExchange(t, published, clientPort5, wan1, 2*time.Second)
	if !bytes.HasPrefix(wan1Result.resp, []byte("ACK1")) {
		t.Fatalf("WAN1 reply = %q, want an ACK1 control frame", wan1Result.resp)
	}
	if wan1Result.from != published {
		t.Fatalf("ACK1 source %s, want the published tuple %s", wan1Result.from, published)
	}
	waitEvent(t, resultsFile, "probe-matched")
	// Replay of the same WAN1 is consumed and dropped (never forwarded).
	if res := labEnv.vantageSend(t, published, clientPort5, wan1, 800*time.Millisecond); res.got {
		t.Fatalf("replayed WAN1 produced a reply: %q", res.resp)
	}
	waitEvent(t, resultsFile, "probe-matched")
	if res := labEnv.vantageExchange(t, published, clientPort5, []byte("ping-9"), 2*time.Second); string(res.resp) != "B:ping-9" {
		t.Fatalf("business path after probe exchange = %q", res.resp)
	}

	// S5: session cap — with a cap of 3, a 4-client burst accepts exactly 3
	// and rejects the 4th (no response, rejection recorded by the child).
	time.Sleep(2500 * time.Millisecond)
	waitStatsActive(t, resultsFile, 0)
	if got := labEnv.vantageBurst(t, published, burstBase, 4, []byte("cap-test"), 1200*time.Millisecond); got != 3 {
		t.Fatalf("session cap accepted %d/4 concurrent clients, want 3", got)
	}
	waitStats(t, resultsFile, func(ev map[string]any) bool {
		active, _ := ev["active"].(float64)
		rejected, _ := ev["rejected"].(float64)
		return int(active) == 3 && rejected >= 1
	})

	// Ordered shutdown: the child closes the forwarder, releases the UDP
	// lease and its store, then exits zero.
	writeCmd(t, cmdFile, "close")
	select {
	case err := <-childDone:
		t.Logf("agent child output:\n%s", childOutput.String())
		if err != nil {
			t.Fatalf("agent child cleanup failed: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("agent child did not exit after close command")
	}
	if ev := waitEvent(t, resultsFile, "closed"); ev != nil {
		if active, _ := ev["active"].(float64); active != 0 {
			t.Fatalf("child closed with %d live sessions, want 0", int(active))
		}
	}
}

// TestUDPAgentChild runs inside the agent namespace. It wires the production
// UDP forwarder exactly as the agent composition root does — UDP lease from
// the socket registry, the reconcile.ProbeManager strict classifier over a
// real localstate store and node key — arms a probe bound to the vantage
// client source, writes the signed WAN1 frame for the parent, publishes the
// forwarder tuple, then applies parent commands (backend hot update, ordered
// close) while streaming stats evidence.
func TestUDPAgentChild(t *testing.T) {
	if os.Getenv("ANTINAT_LAB_MODE") != "agent" {
		t.Skip("child-only: run through TestUDP")
	}
	agentIP := netip.MustParseAddr(os.Getenv("ANTINAT_LAB_AGENT_IP"))
	clientIP := netip.MustParseAddr(os.Getenv("ANTINAT_LAB_CLIENT_IP"))
	echoA := os.Getenv("ANTINAT_LAB_ECHO_A")
	echoB := os.Getenv("ANTINAT_LAB_ECHO_B")
	resultsPath := os.Getenv("ANTINAT_LAB_RESULTS")
	cmdPath := os.Getenv("ANTINAT_LAB_CMD")
	stateDir := os.Getenv("ANTINAT_LAB_STATE_DIR")

	var logMu sync.Mutex
	logEvent := func(ev map[string]any) {
		raw, err := json.Marshal(ev)
		if err != nil {
			return
		}
		logMu.Lock()
		defer logMu.Unlock()
		f, err := os.OpenFile(resultsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		_, _ = f.Write(append(raw, '\n'))
		_ = f.Close()
	}

	store, err := localstate.Open(filepath.Join(stateDir, "state"))
	if err != nil {
		t.Fatalf("open localstate: %v", err)
	}
	nodeKey, err := security.LoadOrCreateNodeKey(filepath.Join(stateDir, "key"), 1)
	if err != nil {
		t.Fatalf("node key: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()

	registry := traversal.NewPortRegistry()
	lease, err := registry.AcquireUDP(ctx, "udp-lab", traversal.TupleKey{
		Family: "ipv4", Protocol: "udp", Address: agentIP.String(), Port: 0,
	})
	if err != nil {
		t.Fatalf("acquire UDP ingress: %v", err)
	}
	published := netip.AddrPortFrom(agentIP, lease.Actual.Port).String()
	t.Logf("forwarder ingress bound at %s", published)

	// Register the applied forward the probe arm must match.
	applied := protocol.AppliedForwardState{
		ForwardID:       "udp-lab",
		SpecRevision:    1,
		DesiredRevision: 1,
		ActualBindHost:  agentIP.String(),
		ActualBindPort:  lease.Actual.Port,
		Strategy:        "direct-v4",
		LayerVersion:    1,
		AppliedAtUnix:   time.Now().Unix(),
	}
	if _, err := store.CommitDesired(protocol.DesiredState{
		NodeID: "udp-lab-node",
		Forwards: []protocol.ForwardSpec{{
			ForwardID: "udp-lab", Protocol: protocol.ProtocolUDP,
			Target: echoA, Strategy: protocol.StrategyDirectV4,
			DesiredRevision: 1, Presence: protocol.PresencePresent,
		}},
	}, []localstate.ForwardApply{{ForwardID: "udp-lab", Outcome: localstate.ApplyApplied, Applied: &applied}}); err != nil {
		t.Fatalf("commit applied forward: %v", err)
	}

	// The production probe plane, wired exactly as the agent does.
	probeMgr := reconcile.NewProbeManager(reconcile.ProbeManagerOptions{
		Store:   store,
		NodeKey: nodeKey,
		Clock:   time.Now,
		SendControl: func(_ context.Context, messageType string, payload []byte) error {
			logEvent(map[string]any{"event": "receipt", "type": messageType, "len": len(payload)})
			return nil
		},
	})

	// Arm a probe whose WAN1 is expected from the vantage client source.
	_, providerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("provider key: %v", err)
	}
	var probeID, providerID, activation, opaque [16]byte
	if _, err := rand.Read(probeID[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(providerID[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(opaque[:]); err != nil {
		t.Fatal(err)
	}
	activation = protocol.ActivationID("udp-lab", 1)
	arm := protocol.ProbeArm{
		ProbeID:           probeID,
		ProviderID:        providerID,
		ProviderPublicKey: [32]byte(providerPriv.Public().(ed25519.PublicKey)),
		ExpectedSourceIP:  clientIP.Unmap().As4(),
		Activation:        activation,
		Endpoint:          published,
		TTLMS:             60000,
		ExpiryOpaque:      opaque,
	}
	if _, err := probeMgr.HandleProbeArm(ctx, arm.Canonical(), "udp-lab"); err != nil {
		t.Fatalf("arm probe: %v", err)
	}

	// Signed WAN1 frame for the parent to send from the vantage namespace.
	var challenge [protocol.ProbeNonceLen]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		t.Fatal(err)
	}
	frame := protocol.ProviderFrame{
		ArmDigest: arm.Digest(), ProbeID: arm.ProbeID, ProviderID: arm.ProviderID,
		Activation: arm.Activation, Endpoint: arm.Endpoint,
		ExpiryOpaque: arm.ExpiryOpaque, Challenge: challenge,
	}
	frame.Signature = ed25519.Sign(providerPriv, frame.SigningBytes())
	wan1 := append(frame.Canonical(), frame.Signature...)
	if err := os.WriteFile(filepath.Join(filepath.Dir(resultsPath), "wan1.bin"), wan1, 0o600); err != nil {
		t.Fatalf("write WAN1 frame: %v", err)
	}

	backend, err := forward.NewBackend(echoA)
	if err != nil {
		t.Fatalf("backend A: %v", err)
	}

	// The strict one-socket classifier from the agent composition root: a
	// full-match WAN1 is consumed at the control path and never reaches the
	// business forwarder.
	classifier := udpforward.ClassifierFunc(func(p udpforward.Packet) udpforward.Classification {
		res := probeMgr.HandleUDPProbe("udp-lab", p.Source, p.Data)
		if !res.Matched {
			return udpforward.Classification{}
		}
		logEvent(map[string]any{"event": "probe-matched", "probe_id": hex.EncodeToString(res.ProbeID[:]), "ack_len": len(res.ACK)})
		return udpforward.Classification{
			Matched: true,
			Reply:   res.ACK,
			OnReply: func(replyErr error) {
				if replyErr != nil {
					return
				}
				_ = probeMgr.MarkUDPProbeACKSent(res.ProbeID)
				probeMgr.SendUDPProbeReceipt(res)
			},
		}
	})

	fwd, err := udpforward.New(lease.Conn, udpforward.Options{
		Backend:          backend,
		Classifiers:      []udpforward.Classifier{classifier},
		IdleTimeout:      1500 * time.Millisecond,
		SweepInterval:    500 * time.Millisecond,
		DialTimeout:      3 * time.Second,
		MaxSessions:      3,
		MaxSessionsPerIP: 3,
		OnReject:         func(err error) { logEvent(map[string]any{"event": "reject", "err": err.Error()}) },
		OnTruncated:      func() { logEvent(map[string]any{"event": "truncated"}) },
	})
	if err != nil {
		t.Fatalf("build UDP forwarder: %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	cleanupOnce := false
	t.Cleanup(func() {
		if cleanupOnce {
			return
		}
		cleanupOnce = true
		runCancel()
		_ = fwd.CloseContext(context.Background())
		_ = lease.Release()
		probeMgr.Close()
		_ = store.Close()
	})
	go func() { _ = fwd.Run(runCtx) }()

	// Periodic stats evidence for the parent's assertions.
	stopStats := make(chan struct{})
	defer close(stopStats)
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				st := fwd.Stats()
				logEvent(map[string]any{
					"event": "stats", "ts": time.Now().UnixMilli(),
					"accepted": st.Accepted, "rejected": st.Rejected, "truncated": st.Truncated,
					"active": st.Active, "fds": st.FDs, "buffers": st.Buffers, "ephemeral": st.Ephemeral,
				})
			case <-stopStats:
				return
			}
		}
	}()

	logEvent(map[string]any{"event": "ready", "published": published, "probe_id": hex.EncodeToString(probeID[:])})

	// Command loop driven by the parent.
	processed := 0
	for {
		select {
		case <-ctx.Done():
			t.Fatal("child timed out waiting for parent commands")
		default:
		}
		raw, err := os.ReadFile(cmdPath)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		var lines []string
		for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
			if line != "" {
				lines = append(lines, line)
			}
		}
		if len(lines) <= processed {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		newLines := lines[processed:]
		processed = len(lines)
		for _, line := range newLines {
			switch strings.TrimSpace(line) {
			case "target=b":
				if err := backend.Update(echoB); err != nil {
					t.Fatalf("hot update to B: %v", err)
				}
				logEvent(map[string]any{"event": "hotupdate", "target": echoB})
				t.Logf("backend hot-updated to %s", echoB)
			case "target=a":
				if err := backend.Update(echoA); err != nil {
					t.Fatalf("hot update to A: %v", err)
				}
				logEvent(map[string]any{"event": "hotupdate", "target": echoA})
				t.Logf("backend hot-updated to %s", echoA)
			case "close":
				runCancel()
				if err := fwd.CloseContext(context.Background()); err != nil {
					t.Errorf("close forwarder: %v", err)
				}
				_ = lease.Release()
				probeMgr.Close()
				_ = store.Close()
				cleanupOnce = true
				st := fwd.Stats()
				logEvent(map[string]any{"event": "closed", "active": st.Active,
					"accepted": st.Accepted, "rejected": st.Rejected, "truncated": st.Truncated})
				t.Logf("child closed: active=%d accepted=%d rejected=%d truncated=%d",
					st.Active, st.Accepted, st.Rejected, st.Truncated)
				return
			default:
				t.Errorf("unknown child command %q", line)
			}
		}
	}
}
