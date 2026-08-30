//go:build linux && netns

// P12 TCP traversal lab (Story 7): drives the real traversal adapters
// (PCP, NAT-PMP, UPnP IGD) inside a network-namespace topology against a
// real gateway daemon (miniupnpd) and a real STUN server (coturn), with an
// independent vantage client verifying every mapped TCP data path. The lab
// is Linux-only real-daemon evidence; no real CPE/router inventory exists,
// so adapters remain experimental per the frozen support matrix.
//
// Run: sudo -E go test -tags=netns ./test/integration -run TestTCPTraversal -count=1 -v
package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
	"github.com/gxbrave/AntiNAT/internal/traversal"
	"github.com/gxbrave/AntiNAT/internal/traversal/natpmp"
	"github.com/gxbrave/AntiNAT/internal/traversal/pcp"
	"github.com/gxbrave/AntiNAT/internal/traversal/stun"
	"github.com/gxbrave/AntiNAT/internal/traversal/upnp"
)

// lab coordinates are parsed from test/netns/traversal_lab.sh.
type lab struct {
	prefix       string
	script       string
	agentNS      string
	cpeNS        string
	vantageNS    string
	gateway      string
	stun         string
	cpeWAN       string
	vantageIP    string
	workDir      string
	miniupnpdPID string
	turnPID      string
}

func requireLabPrerequisites(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("netns lab requires root; run with sudo -E")
	}
	for _, command := range []string{"ip", "nft", "miniupnpd", "turnserver", "bash"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("netns lab prerequisite %s unavailable: %v", command, err)
		}
	}
}

// startLab creates a live topology in keep mode and registers teardown.
func startLab(t *testing.T) *lab {
	t.Helper()
	script, err := filepath.Abs(filepath.Join("..", "netns", "traversal_lab.sh"))
	if err != nil {
		t.Fatalf("locate lab script: %v", err)
	}
	prefix := fmt.Sprintf("antinat-p12-t%d", os.Getpid())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", script)
	cmd.Env = append(os.Environ(),
		"ANTINAT_P12_KEEP=1",
		"ANTINAT_P12_PREFIX="+prefix,
	)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("lab script timed out:\n%s", output)
	}
	if err != nil {
		t.Fatalf("lab script failed: %v\n%s", err, output)
	}

	l := &lab{prefix: prefix, script: script}
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "GATEWAY":
			l.gateway = value
		case "STUN":
			l.stun = value
		case "CPE_WAN":
			l.cpeWAN = value
		case "VANTAGE":
			l.vantageIP = value
		case "AGENT_NS":
			l.agentNS = value
		case "CPE_NS":
			l.cpeNS = value
		case "VANTAGE_NS":
			l.vantageNS = value
		case "WORK_DIR":
			l.workDir = value
		case "MINIUPNPD_PID":
			l.miniupnpdPID = value
		case "TURN_PID":
			l.turnPID = value
		}
	}
	if l.gateway == "" || l.stun == "" || l.agentNS == "" || l.workDir == "" {
		t.Fatalf("lab script output missing topology markers:\n%s", output)
	}
	t.Logf("lab topology: gateway=%s stun=%s cpe_wan=%s vantage=%s",
		l.gateway, l.stun, l.cpeWAN, l.vantageIP)
	t.Cleanup(l.teardown)
	return l
}

func (l *lab) teardown() {
	cmd := exec.Command("bash", l.script)
	cmd.Env = append(os.Environ(),
		"ANTINAT_P12_TEARDOWN=1",
		"ANTINAT_P12_PREFIX="+l.prefix,
		"ANTINAT_P12_WORK_DIR="+l.workDir,
		"ANTINAT_P12_MINIUPNPD_PID="+l.miniupnpdPID,
		"ANTINAT_P12_TURN_PID="+l.turnPID,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "lab teardown failed: %v\n%s", err, output)
	}
	namespaces, _ := exec.Command("ip", "netns", "list").CombinedOutput()
	if strings.Contains(string(namespaces), l.prefix) {
		fmt.Fprintf(os.Stderr, "lab namespace leaked after cleanup:\n%s", namespaces)
	}
}

// vantageConnect dials the CPE WAN mapping from the independent vantage.
func (l *lab) vantageConnect(port uint16, send string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	script := fmt.Sprintf(
		"exec 3<>/dev/tcp/%s/%d; printf '%%s' '%s' >&3; head -c 64 <&3",
		l.cpeWAN, port, send)
	output, err := exec.CommandContext(ctx, "ip", "netns", "exec", l.vantageNS,
		"bash", "-c", script).CombinedOutput()
	if ctx.Err() != nil {
		return "", fmt.Errorf("vantage connect timed out")
	}
	return string(output), err
}

// vantageExpectClosed verifies a released external port no longer accepts
// connections from the vantage. Note the limit: from outside, a removed
// DNAT rule and a closed backend are indistinguishable (both RST) — the
// authoritative gateway-side evidence is gatewayRuleAbsent below; the
// adapters' own delete verification is the ownership proof.
func (l *lab) vantageExpectClosed(port uint16, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	script := fmt.Sprintf("exec 3<>/dev/tcp/%s/%d", l.cpeWAN, port)
	_, err := exec.CommandContext(ctx, "ip", "netns", "exec", l.vantageNS,
		"bash", "-c", script).CombinedOutput()
	if err == nil {
		return fmt.Errorf("port %d still accepts connections after release", port)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("port %d connect hung after release (still filtered open?)", port)
	}
	return nil
}

// gatewayRuleAbsent asserts the CPE's nftables ruleset holds no forward
// rule for the released external port: the gateway-side mapping is really
// gone, not merely unreachable (lifecycle review finding).
func (l *lab) gatewayRuleAbsent(port uint16) error {
	out, err := exec.Command("ip", "netns", "exec", l.cpeNS, "nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		return fmt.Errorf("list gateway ruleset: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, fmt.Sprintf("tcp dport %d", port)) {
			return fmt.Errorf("gateway still holds a forward rule for port %d: %s", port, strings.TrimSpace(line))
		}
	}
	return nil
}

// TestTCPTraversal starts the real daemons, runs the agent child inside its
// namespace, waits for the child to acquire three live mappings, verifies
// them from the independent vantage while the listeners remain open, then
// signals the child to release its local resources.
func TestTCPTraversal(t *testing.T) {
	requireLabPrerequisites(t)
	if os.Getenv("ANTINAT_LAB_MODE") != "" {
		return
	}
	labEnv := startLab(t)

	resultsFile := filepath.Join(labEnv.workDir, "results.txt")
	doneFile := filepath.Join(labEnv.workDir, "done")
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	child := exec.Command("ip", "netns", "exec", labEnv.agentNS, executable,
		"-test.run=TestTCPTraversalAgentChild", "-test.v", "-test.timeout=120s")
	child.Env = append(os.Environ(),
		"ANTINAT_LAB_MODE=agent",
		"ANTINAT_LAB_GATEWAY="+labEnv.gateway,
		"ANTINAT_LAB_STUN="+labEnv.stun,
		"ANTINAT_LAB_CPE_WAN="+labEnv.cpeWAN,
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

	// A failed parent assertion must still let the child exit before the
	// namespace teardown.
	t.Cleanup(func() {
		_ = os.WriteFile(doneFile, []byte("done\n"), 0o600)
		if child.ProcessState == nil {
			_ = child.Process.Kill()
		}
	})

	// Wait until all three mapping records are fsynced while the child keeps
	// the listeners live.
	deadline := time.Now().Add(45 * time.Second)
	var resultBytes []byte
	for time.Now().Before(deadline) {
		select {
		case err := <-childDone:
			t.Fatalf("agent child exited before vantage verification: %v\n%s", err, childOutput.String())
		default:
		}
		resultBytes, _ = os.ReadFile(resultsFile)
		if len(strings.Fields(string(resultBytes))) >= 6 { // 3 x (mechanism port)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(strings.Fields(string(resultBytes))) < 6 {
		t.Fatalf("agent child did not record three mappings:\n%s", childOutput.String())
	}

	scanner := bufio.NewScanner(strings.NewReader(string(resultBytes)))
	var recordedPorts []uint16
	verified := 0
	for scanner.Scan() {
		var mechanism string
		var port uint16
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
		recordedPorts = append(recordedPorts, port)
		verified++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan child results: %v", err)
	}
	if verified != 3 {
		t.Fatalf("verified %d mappings, want exactly 3 (pcp, nat-pmp, upnp-igd)", verified)
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

	// Ownership evidence through the real gateway: after the child released
	// its mappings, the CPE's nftables ruleset must hold no forward rule
	// for any released port (gateway-side truth), and the ports must be
	// closed from the vantage (supplementary reachability check).
	for _, port := range recordedPorts {
		if err := labEnv.gatewayRuleAbsent(port); err != nil {
			t.Errorf("release verification: %v", err)
		}
		if err := labEnv.vantageExpectClosed(port, 3*time.Second); err != nil {
			t.Errorf("release verification: %v", err)
		}
	}
}

// TestTCPTraversalAgentChild runs inside the agent namespace. It drives the
// full per-Forward Manager pipeline — LeaseSource shared-port listeners, the
// real PCP/NAT-PMP/UPnP adapters, the same-tuple STUN observation through
// coturn, the strategy evaluation, the mapping journal and the §3.5 renewal
// loop — records the live mapped ports, waits while the parent probes from
// the vantage, then releases every acquisition and asserts the gateway-side
// deletes succeeded.
func TestTCPTraversalAgentChild(t *testing.T) {
	if os.Getenv("ANTINAT_LAB_MODE") != "agent" {
		t.Skip("child-only: run through TestTCPTraversal")
	}
	gateway, err := netip.ParseAddr(os.Getenv("ANTINAT_LAB_GATEWAY"))
	if err != nil {
		t.Fatalf("lab gateway: %v", err)
	}
	cpeWAN := netip.MustParseAddr(os.Getenv("ANTINAT_LAB_CPE_WAN"))
	stunServer := netip.MustParseAddrPort(os.Getenv("ANTINAT_LAB_STUN"))
	results, err := os.Create(os.Getenv("ANTINAT_LAB_RESULTS"))
	if err != nil {
		t.Fatalf("open results file: %v", err)
	}
	defer results.Close()
	record := func(mechanism string, port uint16) {
		fmt.Fprintf(results, "%s %d\n", mechanism, port)
		_ = results.Sync()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// The lab host is behind the CPE NAT: direct-v4 must classify
	// NO_GLOBAL_V4_SOURCE — the honest precondition for the gateway
	// strategies.
	_, capability, assessErr := traversal.Assess(traversal.HostRouteTable{})
	if assessErr != nil && capability == "" {
		t.Fatalf("assess inside agent ns: %v", assessErr)
	}
	if capability != traversal.CapabilityNoGlobalV4Source {
		t.Fatalf("lab source must classify NO_GLOBAL_V4_SOURCE, got %s", capability)
	}
	// The gateway strategies map the default-route interface's own (private)
	// address — the manager resolves it, not the test.
	selection, err := traversal.DefaultRouteSource(traversal.HostRouteTable{})
	if err != nil {
		t.Fatalf("default-route source inside agent ns: %v", err)
	}
	internalIP := selection.Source
	t.Logf("agent ns internal IP: %s on %s (private=%v); direct-v4=%s",
		internalIP, selection.Interface, !selection.Global, capability)

	// The composition root wiring for forwards that need the same-tuple
	// STUN observation: shared-port listeners + the same-tuple observer.
	journal := traversal.NewMemoryJournal()
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

	var acquisitions []*traversal.Acquisition
	for _, mechanism := range []traversal.MappingLayerKind{traversal.LayerPCP, traversal.LayerNATPMP, traversal.LayerUPnP} {
		forwardID := "lab-" + string(mechanism)
		request := traversal.AcquireRequest{
			ForwardID: forwardID,
			Owner:     forwardID,
			Spec: protocol.ForwardSpec{
				ForwardID: forwardID, Protocol: protocol.ProtocolTCP,
				Strategy: protocol.StrategyExplicitGateway,
			},
			Plan:       planFor(mechanism),
			Lease:      10 * time.Minute,
			StunServer: "stun+tcp://" + stunServer.String(),
		}
		acquisition, err := manager.Acquire(ctx, request)
		if err != nil {
			t.Fatalf("%s acquire: %v", mechanism, err)
		}
		acquisitions = append(acquisitions, acquisition)

		if acquisition.StunObserveError != nil {
			t.Fatalf("%s same-tuple STUN observation: %v", mechanism, acquisition.StunObserveError)
		}
		if len(acquisition.Layers) != 2 {
			t.Fatalf("%s layers = %+v, want the gateway layer plus the same-tuple STUN layer", mechanism, acquisition.Layers)
		}
		stunLayer := acquisition.Layers[1]
		if stunLayer.Kind != traversal.LayerKindSTUN || stunLayer.ParentLayer != 0 {
			t.Fatalf("%s stun layer = %+v, want a child of the gateway layer", mechanism, stunLayer)
		}
		observed, err := netip.ParseAddrPort(stunLayer.AssignedEndpoint)
		if err != nil {
			t.Fatalf("%s stun endpoint: %v", mechanism, err)
		}
		if observed.Addr() != cpeWAN {
			t.Fatalf("%s STUN mapped address = %s, want CPE WAN %s", mechanism, observed.Addr(), cpeWAN)
		}
		mapping := acquisition.Mapping
		if mapping == nil || mapping.External.Port() == 0 {
			t.Fatalf("%s mapping = %+v, want a live external port", mechanism, mapping)
		}
		if mapping.External.Addr() != cpeWAN {
			t.Fatalf("%s external address = %s, want CPE WAN %s", mechanism, mapping.External.Addr(), cpeWAN)
		}
		if acquisition.JournalID == "" {
			t.Fatalf("%s acquisition must reference its journal record", mechanism)
		}
		records, err := journal.ListByForward(forwardID)
		if err != nil || len(records) != 1 {
			t.Fatalf("%s journal records = %v/%v", mechanism, records, err)
		}
		t.Logf("%s acquired: internal=:%d external=%s observed=%s ownership=%s verdict=%s",
			mechanism, mapping.InternalPort, mapping.External, observed, mapping.Ownership,
			acquisition.Verdict.Scope)

		// The manager's listener is the forward data plane: serve the echo
		// the vantage probes will send.
		serveEcho(acquisition.Listener)
		record(string(mechanism), mapping.External.Port())
	}

	// Wait for the parent's vantage verification, then release everything:
	// the §3.4 ownership discipline deletes the real gateway mappings.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(os.Getenv("ANTINAT_LAB_DONE")); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, acquisition := range acquisitions {
		if err := acquisition.Release(ctx); err != nil {
			t.Errorf("%s release: %v", acquisition.ForwardID, err)
		}
	}
	remaining, err := journal.List()
	if err != nil || len(remaining) != 0 {
		t.Errorf("journal after release = %v/%v, want no records left", remaining, err)
	}
	if t.Failed() {
		return
	}
	t.Log("child released all three acquisitions; gateway deletes verified by the parent")
}

// planFor resolves the explicit-gateway plan for one mechanism.
func planFor(mechanism traversal.MappingLayerKind) traversal.PlanRequest {
	return traversal.PlanRequest{
		Strategy:     protocol.StrategyExplicitGateway,
		MappingLayer: mechanism,
	}
}

// serveEcho answers vantage probes on the manager-acquired listener until
// Release closes it.
func serveEcho(listener net.Listener) {
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 64)
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, _ := conn.Read(buf)
				fmt.Fprintf(conn, "ANTINAT-ECHO:%s", buf[:n])
			}(conn)
		}
	}()
}
