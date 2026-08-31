//go:build linux && netns

// P12W Story 9: the composed P12W gateway composition against real daemons.
// Inside the lab agent namespace a data plane wired exactly like the composed
// app — the store-backed bbolt mapping journal (Story 1), the real PCP/NAT-PMP/
// UPnP adapters and the shared-port same-tuple STUN observer (Story 2) — applies
// an explicit-gateway TCP forward. The independent vantage verifies the mapped
// external port, then release deletes the gateway mapping and the journal; the
// CPE nft ruleset must hold no forward rule afterwards.
//
// Run: sudo -E go test -tags=netns ./test/integration -run TestAgentGatewayTraversal -count=1 -v
package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/traversal"
	"github.com/gxbrave/AntiNAT/internal/traversal/natpmp"
	"github.com/gxbrave/AntiNAT/internal/traversal/pcp"
	"github.com/gxbrave/AntiNAT/internal/traversal/stun"
	"github.com/gxbrave/AntiNAT/internal/traversal/upnp"
)

// TestAgentGatewayTraversal starts the real daemons, runs the composed child
// inside its namespace, verifies the mapped external port from the independent
// vantage, then signals the child to release and asserts the gateway-side
// ownership evidence (no forward rule in the CPE nft ruleset).
func TestAgentGatewayTraversal(t *testing.T) {
	requireLabPrerequisites(t)
	if os.Getenv("ANTINAT_LAB_MODE") != "" {
		return
	}
	labEnv := startLab(t)

	resultsFile := filepath.Join(labEnv.workDir, "results-gw.txt")
	doneFile := filepath.Join(labEnv.workDir, "done-gw")
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	child := exec.Command("ip", "netns", "exec", labEnv.agentNS, executable,
		"-test.run=TestAgentGatewayTraversalChild", "-test.v", "-test.timeout=120s")
	child.Env = append(os.Environ(),
		"ANTINAT_LAB_MODE=agent",
		"ANTINAT_LAB_GATEWAY="+labEnv.gateway,
		"ANTINAT_LAB_STUN="+labEnv.stun,
		"ANTINAT_LAB_CPE_WAN="+labEnv.cpeWAN,
		"ANTINAT_LAB_WORK_DIR="+labEnv.workDir,
		"ANTINAT_LAB_RESULTS="+resultsFile,
		"ANTINAT_LAB_DONE="+doneFile,
	)
	var childOutput bytes.Buffer
	child.Stdout = &childOutput
	child.Stderr = &childOutput
	if err := child.Start(); err != nil {
		t.Fatalf("start agent child: %v", err)
	}
	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()
	t.Cleanup(func() {
		_ = os.WriteFile(doneFile, []byte("done\n"), 0o600)
		if child.ProcessState == nil {
			_ = child.Process.Kill()
		}
	})

	// Wait until the composed child records its one mapped port while the
	// listener stays live.
	deadline := time.Now().Add(45 * time.Second)
	var resultBytes []byte
	for time.Now().Before(deadline) {
		select {
		case err := <-childDone:
			t.Fatalf("agent child exited before vantage verification: %v\n%s", err, childOutput.String())
		default:
		}
		resultBytes, _ = os.ReadFile(resultsFile)
		if len(strings.Fields(string(resultBytes))) >= 2 { // 1 x (mechanism port)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(strings.Fields(string(resultBytes))) < 2 {
		t.Fatalf("agent child did not record a mapping:\n%s", childOutput.String())
	}

	var mechanism string
	var port uint16
	scanner := bufio.NewScanner(strings.NewReader(string(resultBytes)))
	verified := false
	for scanner.Scan() {
		if _, err := fmt.Sscanf(scanner.Text(), "%s %d", &mechanism, &port); err != nil {
			continue
		}
		t.Logf("verifying %s mapping %s:%d from the vantage", mechanism, labEnv.cpeWAN, port)
		response, err := labEnv.vantageConnect(port, "ping-"+mechanism, 5*time.Second)
		if err != nil {
			t.Fatalf("%s mapping not reachable from the vantage: %v\n%s", mechanism, err, childOutput.String())
		}
		if !strings.Contains(response, "ANTINAT-ECHO") {
			t.Fatalf("%s mapping response = %q, want the echo banner", mechanism, response)
		}
		verified = true
	}
	if !verified {
		t.Fatalf("no usable mapping recorded:\n%s", resultBytes)
	}

	if err := os.WriteFile(doneFile, []byte("done\n"), 0o600); err != nil {
		t.Fatalf("signal child cleanup: %v", err)
	}
	select {
	case err := <-childDone:
		t.Logf("agent child output:\n%s", childOutput.String())
		if err != nil {
			t.Fatalf("agent child cleanup failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent child did not exit after cleanup signal")
	}

	if err := labEnv.gatewayRuleAbsent(port); err != nil {
		t.Errorf("release verification: %v", err)
	}
	if err := labEnv.vantageExpectClosed(port, 3*time.Second); err != nil {
		t.Errorf("release verification: %v", err)
	}
}

// TestAgentGatewayTraversalChild runs inside the agent namespace with the
// composed P12W data-plane wiring: the STORE-BACKED bbolt mapping journal (the
// agent's localstate MappingJournal), the real adapters registered exactly like
// New(), and the shared-port same-tuple STUN observer.
func TestAgentGatewayTraversalChild(t *testing.T) {
	if os.Getenv("ANTINAT_LAB_MODE") != "agent" {
		t.Skip("child-only: run through TestAgentGatewayTraversal")
	}
	gateway, err := netip.ParseAddr(os.Getenv("ANTINAT_LAB_GATEWAY"))
	if err != nil {
		t.Fatalf("lab gateway: %v", err)
	}
	stunServer := netip.MustParseAddrPort(os.Getenv("ANTINAT_LAB_STUN"))
	workDir := os.Getenv("ANTINAT_LAB_WORK_DIR")
	if workDir == "" {
		t.Fatal("lab work dir is required")
	}
	results, err := os.Create(os.Getenv("ANTINAT_LAB_RESULTS"))
	if err != nil {
		t.Fatalf("open results file: %v", err)
	}
	defer results.Close()
	record := func(mechanism string, port uint16) {
		fmt.Fprintf(results, "%s %d\n", mechanism, port)
		_ = results.Sync()
	}

	// The composed app's durable journal: the Agent bbolt mapping_journal.
	st, err := localstate.Open(filepath.Join(workDir, "agent-state"))
	if err != nil {
		t.Fatalf("open localstate: %v", err)
	}
	defer st.Close()
	journal := st.MappingJournal()

	// The app composition root (P12W New()): default-route source + real
	// adapters registered the same way composeTraversal does.
	selection, err := traversal.DefaultRouteSource(traversal.HostRouteTable{})
	if err != nil {
		t.Fatalf("default-route source inside agent ns: %v", err)
	}
	internalIP := selection.Source
	manager := traversal.NewManager(traversal.ManagerOptions{
		RouteTable: traversal.HostRouteTable{},
		Listeners:  stun.LeaseSource{Registry: stun.NewSharedPortRegistry()},
		Mappers: map[traversal.MappingLayerKind]traversal.GatewayMapper{
			traversal.LayerPCP: pcp.NewAdapter(pcp.AdapterOptions{
				Gateway: netip.AddrPortFrom(gateway, pcp.DefaultServerPort), Timeout: 3 * time.Second,
			}),
			traversal.LayerNATPMP: natpmp.NewAdapter(natpmp.AdapterOptions{
				Gateway: netip.AddrPortFrom(gateway, natpmp.DefaultServerPort), Timeout: 3 * time.Second,
			}),
			traversal.LayerUPnP: upnp.NewAdapter(upnp.AdapterOptions{
				InterfaceIP: internalIP, Timeout: 5 * time.Second,
			}),
		},
		Journal:     journal,
		StunObserve: stun.NewManagerObserver(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// One explicit-gateway PCP forward, exactly as the dataPlane's strategy
	// router would produce it.
	acquisition, err := manager.Acquire(ctx, traversal.AcquireRequest{
		ForwardID: "agent-gateway-fwd",
		Owner:     "agent-gateway-fwd",
		Spec: protocol.ForwardSpec{
			ForwardID: "agent-gateway-fwd", Protocol: protocol.ProtocolTCP,
			Strategy: protocol.StrategyExplicitGateway,
		},
		Plan:       traversal.PlanRequest{Strategy: protocol.StrategyExplicitGateway, MappingLayer: traversal.LayerPCP},
		Lease:      10 * time.Minute,
		StunServer: "stun+tcp://" + stunServer.String(),
	})
	if err != nil {
		t.Fatalf("composed gateway acquire: %v", err)
	}
	if acquisition.StunObserveError != nil {
		t.Fatalf("same-tuple STUN observation: %v", acquisition.StunObserveError)
	}
	if acquisition.JournalID == "" {
		t.Fatal("acquisition must reference a durable journal record")
	}
	if records, err := journal.ListByForward("agent-gateway-fwd"); err != nil || len(records) != 1 {
		t.Fatalf("journal records = %+v, err=%v; want exactly one", records, err)
	}
	mapping := acquisition.CurrentMapping()
	if mapping == nil || mapping.External.Port() == 0 {
		t.Fatalf("mapping = %+v, want a live external port", mapping)
	}
	if mapping.Ownership != traversal.OwnershipStrong {
		t.Fatalf("mapping ownership = %q, want STRONG_PROTOCOL_OWNERSHIP", mapping.Ownership)
	}
	t.Logf("composed gateway acquired: internal=:%d external=%s ownership=%s journal=%s",
		mapping.InternalPort, mapping.External, mapping.Ownership, acquisition.JournalID)

	serveEcho(acquisition.Listener)
	record("pcp", mapping.External.Port())

	// Wait for the parent's vantage verification, then release: the ownership
	// discipline deletes the real gateway mapping AND the durable journal row.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(os.Getenv("ANTINAT_LAB_DONE")); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := acquisition.Release(ctx); err != nil {
		t.Errorf("composed release: %v", err)
	}
	if remaining, err := journal.List(); err != nil || len(remaining) != 0 {
		t.Errorf("store journal after release = %v/%v, want empty", remaining, err)
	}
	if t.Failed() {
		return
	}
	t.Log("composed gateway released; gateway deletes verified by the parent")
}
