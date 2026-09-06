//go:build linux

// M1 walking skeleton (P10 Story 6, v0.8 §11.3 M1-12).
//
// From empty state: init admin -> create node -> enroll (hidden token) ->
// create a Linux direct-v4 TCP Forward -> explicit local no-independent-vantage
// policy (no fabricated OPEN_FROM_VANTAGE evidence) -> external client gets
// the target echo -> target hot update
//
// The orchestrator host has no global IPv4, so the harness aliases a
// global-class literal on loopback and injects a deterministic route table
// into the agent (documented in the P10 handoff; real-WAN evidence is a
// later milestone).
package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/test/e2e/harness"
)

// cliState is a placeholder to keep the file focused on the walking
// skeleton; CLI invocation goes through harness.RunCLI.

func TestLinuxDirectV4WalkingSkeleton(t *testing.T) {
	cleanupAlias := harness.AliasGlobal(t)
	defer cleanupAlias()

	h := harness.NewEnv(t)
	stateDir := t.TempDir()

	// 1. Init admin (CLI) and capture the one-time password.
	out, err := h.RunCLI(stateDir, "admin", "init")
	if err != nil {
		t.Fatalf("admin init: %v (%s)", err, out)
	}
	var password string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 8 && !strings.Contains(line, "admin") &&
			!strings.Contains(line, "password") && !strings.Contains(line, "created") &&
			!strings.Contains(line, "One-time") {
			password = line
			break
		}
	}
	if password == "" {
		t.Fatalf("could not extract generated password from %s", out)
	}
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte(password), 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. Login.
	out, err = h.RunCLI(stateDir, "login", "--username", "admin", "--password-file", pwFile)
	if err != nil || !strings.Contains(out, "logged in") {
		t.Fatalf("login: %v (%s)", err, out)
	}

	// 3. Create a node and issue its one-time enrollment token.
	out, err = h.RunCLI(stateDir, "node", "create", "--name", "node-a")
	if err != nil {
		t.Fatalf("node create: %v (%s)", err, out)
	}
	var node struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &node); err != nil || node.ID == "" {
		t.Fatalf("node create output: %s", out)
	}
	nodeID := node.ID

	out, err = h.RunCLI(stateDir, "node", "token", nodeID)
	if err != nil || !strings.Contains(out, "One-time enrollment token") {
		t.Fatalf("node token: %v (%s)", err, out)
	}
	var token string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 16 && !strings.Contains(line, "token") &&
			!strings.Contains(line, "One-time") {
			token = line
			break
		}
	}
	if token == "" {
		t.Fatalf("could not extract token from %s", out)
	}

	// 4. Agent enrolls with the hidden token and connects the control
	// channel.
	agentDir := t.TempDir()
	app := h.StartAgent(agentDir, nodeID, token)
	defer h.StopAgent()

	// 5. Target echo server, then create the direct-v4 forward.
	echoA, stopA := harness.EchoServer(t, "A:")
	defer stopA()
	echoB, stopB := harness.EchoServer(t, "B:")
	defer stopB()

	out, err = h.RunCLI(stateDir, "forward", "create",
		"--node", nodeID, "--name", "web", "--protocol", "tcp",
		"--target", echoA, "--strategy", "direct-v4")
	if err != nil {
		t.Fatalf("forward create: %v (%s)", err, out)
	}
	var fwd struct {
		ID   string `json:"id"`
		ETag string `json:"etag"`
	}
	if err := json.Unmarshal([]byte(out), &fwd); err != nil || fwd.ID == "" || fwd.ETag == "" {
		t.Fatalf("forward create output: %s", out)
	}
	fwdID := fwd.ID

	// 6. Wait until the agent applied the forward (listener bound on the
	// global literal).
	harness.WaitFor(t, 20*time.Second, "agent applied forward", func() bool {
		st, ok, err := app.Store().GetAppliedState(fwdID)
		return err == nil && ok && st.ActualBindHost == harness.GlobalLiteral
	})
	st, _, _ := app.Store().GetAppliedState(fwdID)
	endpoint := net.JoinHostPort(st.ActualBindHost, fmt.Sprintf("%d", st.ActualBindPort))

	// 7. The local fixture explicitly has no independent vantage. Do not
	// arm a probe against it: the controller's provider policy is covered by
	// the strict manager regression and the end-to-end path must not invent
	// OPEN_FROM_VANTAGE evidence from a loopback service.
	harness.WaitFor(t, 20*time.Second, "initial unverified activation", func() bool {
		snap := app.ActivationSnapshot(fwdID)
		return snap != nil && snap.WanReachabilityState == "NOT_TESTED"
	})

	// 8. External client reaches the published endpoint and gets the target
	// echo characteristics.
	harness.DialEcho(t, endpoint, "ping-1", "A:")

	// 9. Target hot update: old connection stays on the old target, new
	// connections go to the new target.
	oldConn, err := net.DialTimeout("tcp4", endpoint, 5*time.Second)
	if err != nil {
		t.Fatalf("dial before update: %v", err)
	}
	defer oldConn.Close()
	if _, err := oldConn.Write([]byte("ping-old")); err != nil {
		t.Fatal(err)
	}
	_ = oldConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	oldBuf := make([]byte, 16)
	n, _ := oldConn.Read(oldBuf)
	if got := string(oldBuf[:n]); got != "A:ping-old" {
		t.Fatalf("old connection echo = %q, want A:ping-old", got)
	}

	out, err = h.RunCLI(stateDir, "forward", "update", fwdID, "--target", echoB)
	if err != nil {
		t.Fatalf("forward update: %v (%s)", err, out)
	}
	harness.WaitFor(t, 20*time.Second, "agent hot update", func() bool {
		st2, ok, err2 := app.Store().GetAppliedState(fwdID)
		return err2 == nil && ok && st2.SpecRevision >= 2
	})
	// Old connection still on target A.
	if _, err := oldConn.Write([]byte("ping-old-2")); err != nil {
		t.Fatal(err)
	}
	_ = oldConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ = oldConn.Read(oldBuf)
	if got := string(oldBuf[:n]); got != "A:ping-old-2" {
		t.Fatalf("old connection after update = %q, want A:ping-old-2", got)
	}
	// New connection goes to target B.
	harness.DialEcho(t, endpoint, "ping-new", "B:")

	// 10. Agent restart: the listener is restored from the durable applied
	// state, but the activation is UNVERIFIED.
	h.StopAgent()
	app2 := h.StartAgent(agentDir, nodeID, "")
	harness.WaitFor(t, 20*time.Second, "listener restored after restart", func() bool {
		st2, ok, err2 := app2.Store().GetAppliedState(fwdID)
		return err2 == nil && ok && st2.ActualBindPort == st.ActualBindPort
	})
	harness.WaitFor(t, 20*time.Second, "control session online after restart", func() bool {
		n, err := h.Store.GetNode(nodeID)
		return err == nil && n.ControlState == "ONLINE"
	})
	snap := app2.ActivationSnapshot(fwdID)
	if snap == nil {
		t.Fatal("no activation snapshot after restart")
	}
	if snap.WanReachabilityState != "NOT_TESTED" {
		t.Fatalf("after restart WanReachabilityState = %q, want NOT_TESTED (UNVERIFIED)", snap.WanReachabilityState)
	}

	// 11. A local restart remains UNVERIFIED; no provider round trip is
	// fabricated merely because the fixture has a reachable HTTP endpoint.
	if snap2 := app2.ActivationSnapshot(fwdID); snap2 == nil || snap2.WanReachabilityState != "NOT_TESTED" {
		t.Fatalf("after local restart activation claimed WAN evidence: %#v", snap2)
	}
	harness.DialEcho(t, endpoint, "ping-after-restart", "B:")

	// 12. Online delete: the CLI DELETE is accepted with an operation id,
	// the agent stops the listener, and the deletion operation completes.
	out, err = h.RunCLI(stateDir, "forward", "delete", fwdID)
	if err != nil || !strings.Contains(out, "delete accepted") {
		t.Fatalf("forward delete: %v (%s)", err, out)
	}
	var delOp string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "delete accepted: ") {
			delOp = strings.TrimPrefix(line, "delete accepted: ")
			break
		}
	}
	if delOp == "" {
		t.Fatalf("no deletion operation id in %s", out)
	}
	var delLogged bool
	harness.WaitFor(t, 20*time.Second, "deletion COMPLETED", func() bool {
		op, err := h.Store.GetForwardDeletionOperation(delOp)
		if !delLogged && err == nil && op.Status != "COMPLETED" {
			ctrlOutbox, ctrlOutboxErr := h.Store.ControlOutboxItemByOperation(delOp, "forward_delete")
			ctrlDesired, ctrlDesiredErr := h.Store.ControlOutboxItemByOperation(delOp, "desired")
			nodeID := ctrlDesired.NodeID
			ctrlRows, ctrlRowsErr := h.Store.ListControlOutboxByState(nodeID, "PENDING", "CLAIMED", "SENT", "SEMANTIC_ACKED")
			received, receivedErr := h.Store.ListControlInboxByTypeStateLimit(nodeID, "RECEIVED", 20, "operation_complete", "desired_result", "forward_delete_ack")
			agentOutbox, agentOutboxErr := app2.Store().OutboxOperationIDs()
			agentStates := make(map[string]string)
			for _, id := range agentOutbox {
				state, present, stateErr := app2.Store().OutboxState(id)
				if stateErr == nil && present {
					agentStates[id] = state
				}
			}
			events, eventsErr := h.Store.AdminEventsAfter(0, 1000)
			t.Logf("delete diagnostic: delOp=%s status=%q ctrl_forward=%+v ctrl_forward_err=%v ctrl_desired=%+v ctrl_desired_err=%v ctrl_rows=%+v ctrl_rows_err=%v received=%+v received_err=%v agent_outbox=%v agent_states=%v agent_err=%v events=%+v events_err=%v", delOp, op.Status, ctrlOutbox, ctrlOutboxErr, ctrlDesired, ctrlDesiredErr, ctrlRows, ctrlRowsErr, received, receivedErr, agentOutbox, agentStates, agentOutboxErr, events, eventsErr)
			delLogged = true
		}
		return err == nil && op.Status == "COMPLETED"
	})
	// Listener ownership is gone: the exact published endpoint becomes bindable
	// at the OS boundary. This cannot false-pass when a stale listener still
	// accepts connections but its target is unavailable.
	reservation := harness.ReserveReleasedEndpoint(t, endpoint)
	defer reservation.Close()

	// 13. Restart after delete: no resurrection (tombstone-before-stop). Keep the
	// exact endpoint reserved throughout restart so parallel port reuse cannot
	// impersonate the deleted Forward or make the ownership oracle flaky.
	h.StopAgent()
	app3 := h.StartAgent(agentDir, nodeID, "")
	defer h.StopAgent()
	time.Sleep(500 * time.Millisecond)
	if _, ok, _ := app3.Store().GetAppliedState(fwdID); ok {
		t.Fatal("forward resurrected after delete + restart")
	}
}
