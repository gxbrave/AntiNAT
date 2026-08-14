// Package harness composes the M1 walking-skeleton environment: an
// in-process controller app, agent app, probe provider service, echo
// targets, and the antinatctl CLI binary.
//
// The orchestrator host has no global IPv4 (private ens18 only), so the
// harness aliases a global-class literal (8.8.8.8/32) on loopback and
// injects a deterministic route table into the agent app. The full control,
// probe, and data plane then run over real sockets on that literal; real
// WAN evidence remains a later-milestone capability, and this is documented
// in the P10 handoff.
package harness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/agent"
	"github.com/gxbrave/AntiNAT/internal/controller"
	"github.com/gxbrave/AntiNAT/internal/controller/probe"
	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/traversal"
)

// GlobalLiteral is the loopback-aliased global-class source used by the
// walking skeleton (the orchestrator host has no real global IPv4).
const GlobalLiteral = "8.8.8.8"

// fakeRouteTable claims a deterministic direct-v4 topology: the default
// route and the global literal both live on lo. Assess() then reports
// DIRECT_V4_READY with source 8.8.8.8; the alias on lo makes the literal
// bindable and locally reachable.
type fakeRouteTable struct{}

func (fakeRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	return netip.MustParseAddr("127.0.0.1"), "lo", true, nil
}

func (fakeRouteTable) IPv4Addresses() ([]traversal.IPv4Address, error) {
	return []traversal.IPv4Address{{Interface: "lo", Addr: netip.MustParseAddr(GlobalLiteral)}}, nil
}

// AliasGlobal adds the global-class literal to lo and returns a cleanup.
// The walking skeleton requires it; without it the test fails (honest
// capability downgrade, not a fake pass). Idempotent: a leftover alias from
// a crashed run is reused.
func AliasGlobal(t *testing.T) func() {
	t.Helper()
	if out, err := exec.Command("ip", "addr", "add", GlobalLiteral+"/32", "dev", "lo").CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "Address already assigned") {
			t.Fatalf("add loopback alias %s/32: %v (%s) — the walking skeleton needs CAP_NET_ADMIN", GlobalLiteral, err, out)
		}
	}
	return func() {
		_ = exec.Command("ip", "addr", "del", GlobalLiteral+"/32", "dev", "lo").Run()
	}
}

// Env is one walking-skeleton environment.
type Env struct {
	Ctrl        *controller.App
	Agent       *agent.App
	AgentDir    string
	ProviderSrv *httptest.Server
	CLI         string
	Store       *store.Store
	t           *testing.T

	agentCtx    context.Context
	agentCancel context.CancelFunc
}

// NewEnv starts the controller app, the in-process provider service, and
// builds the antinatctl CLI binary. The agent is started separately (it
// needs the enrollment token from the CLI node create).
func NewEnv(t *testing.T) *Env {
	t.Helper()
	ctrl, err := controller.New(controller.Config{
		ListenAddress: "127.0.0.1:0",
		StorePath:     filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:        t.TempDir(),
		Clock:         time.Now,
	})
	if err != nil {
		t.Fatalf("controller New: %v", err)
	}
	if err := ctrl.Start(); err != nil {
		t.Fatalf("controller Start: %v", err)
	}
	t.Cleanup(func() { ctrl.Shutdown(context.Background()) })

	// In-process provider service with its own keypair.
	_, provPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := probe.NewProvider(probe.ProviderConfig{
		ControllerPublicKey: ctrl.Hub().ControllerPublicKey(),
		ProviderPrivateKey:  provPriv,
	})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	if _, err := ctrl.Store().CreateProbeProvider(store.ProbeProvider{
		ID:        "p1",
		Name:      "walking-skeleton-provider",
		PublicKey: hex.EncodeToString(provPriv.Public().(ed25519.PublicKey)),
		EgressIP:  GlobalLiteral,
		Endpoint:  srv.URL,
		Enabled:   true,
	}); err != nil {
		t.Fatalf("register provider: %v", err)
	}

	cli := buildCLI(t)
	return &Env{Ctrl: ctrl, ProviderSrv: srv, CLI: cli, Store: ctrl.Store(), t: t}
}

// buildCLI compiles antinatctl into a temp dir.
func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "antinatctl")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/gxbrave/AntiNAT/cmd/antinatctl")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build antinatctl: %v (%s)", err, out)
	}
	return bin
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// The harness source lives at test/e2e/harness/harness.go: three levels
	// up from the file's directory is the module root. This is robust
	// regardless of the test binary's working directory.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate harness source")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(file))))
}

// RunCLI executes antinatctl with a state dir and returns combined output.
func (e *Env) RunCLI(stateDir string, args ...string) (string, error) {
	full := append([]string{"--endpoint", "http://" + e.Ctrl.Addr(), "--state", stateDir}, args...)
	cmd := exec.Command(e.CLI, full...)
	cmd.Stdin = strings.NewReader("cli-test-password-123\n")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// StartAgent launches the agent app with the given enrollment token (empty
// on restart) and returns it. The control session runs on a context the
// harness keeps alive until StopAgent (the app's loops live on that ctx).
func (e *Env) StartAgent(stateDir, nodeID, token string) *agent.App {
	e.t.Helper()
	app, err := agent.New(agent.Config{
		StateDir:            stateDir,
		Endpoint:            "http://" + e.Ctrl.Addr(),
		NodeID:              nodeID,
		Token:               token,
		ControllerPublicKey: e.Ctrl.Hub().ControllerPublicKey(),
		Heartbeat:           50 * time.Millisecond,
		RouteTable:          fakeRouteTable{},
	})
	if err != nil {
		e.t.Fatalf("agent New: %v", err)
	}
	if e.agentCtx != nil {
		e.agentCancel()
	}
	e.agentCtx, e.agentCancel = context.WithCancel(context.Background())
	if err := app.Start(e.agentCtx); err != nil {
		e.t.Fatalf("agent Start: %v", err)
	}
	e.Agent = app
	e.AgentDir = stateDir
	return app
}

// StopAgent shuts the current agent app down (restart path).
func (e *Env) StopAgent() {
	e.t.Helper()
	if e.Agent != nil {
		if e.agentCtx != nil {
			e.agentCancel()
		}
		if err := e.Agent.Shutdown(context.Background()); err != nil {
			e.t.Fatalf("agent Shutdown: %v", err)
		}
		e.Agent = nil
	}
}

// WaitFor polls fn until it returns true or the timeout elapses.
func WaitFor(t *testing.T, timeout time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// EchoServer runs a TCP echo server that prefixes each echoed line with tag.
func EchoServer(t *testing.T, tag string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					_, _ = c.Write(append([]byte(tag), buf[:n]...))
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// DialEcho connects to the published endpoint and verifies the echoed tag.
func DialEcho(t *testing.T, endpoint, send, wantTag string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", endpoint, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", endpoint, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(send)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(wantTag)+len(send)+1)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(buf[:n])
	want := wantTag + send
	if got != want {
		t.Fatalf("echo = %q, want %q", got, want)
	}
}

// HTTPGet fetches a controller admin URL (no auth needed for healthz).
func HTTPGet(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

var _ = fmt.Sprintf
