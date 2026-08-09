//go:build linux

package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPortRegistryAcquirePortZeroOwnsActualSocketAtomically(t *testing.T) {
	registry := NewPortRegistry()
	lease, err := registry.AcquireTCP(context.Background(), "owner-a", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("acquire port zero: %v", err)
	}
	defer lease.Release()

	actual := lease.Listener.Addr().(*net.TCPAddr)
	if actual.Port == 0 {
		t.Fatal("lease retained port 0")
	}
	competitor, err := net.ListenTCP("tcp4", actual)
	if competitor != nil {
		competitor.Close()
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("competing bind error = %v, want EADDRINUSE", err)
	}
	if got := registry.Len(); got != 1 {
		t.Fatalf("registry length = %d, want 1", got)
	}
}

func TestPortRegistryStaleReleaseCannotCloseNewOwner(t *testing.T) {
	registry := NewPortRegistry()
	oldLease, err := registry.AcquireTCP(context.Background(), "old-owner", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("acquire old lease: %v", err)
	}
	address := oldLease.Listener.Addr().(*net.TCPAddr)
	if err := oldLease.Release(); err != nil {
		t.Fatalf("release old lease: %v", err)
	}
	newLease, err := registry.AcquireTCP(context.Background(), "new-owner", address)
	if err != nil {
		t.Fatalf("acquire new lease: %v", err)
	}
	defer newLease.Release()

	if err := oldLease.Release(); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("late old release error = %v, want ErrStaleLease", err)
	}
	competitor, err := net.ListenTCP("tcp4", address)
	if competitor != nil {
		competitor.Close()
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("new owner socket was not retained: bind error = %v", err)
	}
}

func TestPortRegistryRejectsWildcardSpecificOverlap(t *testing.T) {
	t.Run("specific then wildcard", func(t *testing.T) {
		registry := NewPortRegistry()
		specific, err := registry.AcquireTCP(context.Background(), "specific", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatalf("acquire specific: %v", err)
		}
		defer specific.Release()
		port := specific.Listener.Addr().(*net.TCPAddr).Port
		if _, err := registry.AcquireTCP(context.Background(), "wildcard", &net.TCPAddr{IP: net.IPv4zero, Port: port}); !errors.Is(err, ErrTupleOverlap) {
			t.Fatalf("wildcard overlap error = %v, want ErrTupleOverlap", err)
		}
	})

	t.Run("wildcard then specific", func(t *testing.T) {
		registry := NewPortRegistry()
		wildcard, err := registry.AcquireTCP(context.Background(), "wildcard", &net.TCPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatalf("acquire wildcard: %v", err)
		}
		defer wildcard.Release()
		port := wildcard.Listener.Addr().(*net.TCPAddr).Port
		if _, err := registry.AcquireTCP(context.Background(), "specific", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}); !errors.Is(err, ErrTupleOverlap) {
			t.Fatalf("specific overlap error = %v, want ErrTupleOverlap", err)
		}
	})
}

func TestBindProbeCloseAllowsCompetingProcessToStealTuple(t *testing.T) {
	probe, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("probe bind: %v", err)
	}
	address := probe.Addr().(*net.TCPAddr)
	if err := probe.Close(); err != nil {
		t.Fatalf("probe close: %v", err)
	}
	competitor, err := net.ListenTCP("tcp4", address)
	if err != nil {
		t.Fatalf("competitor acquired probe-closed tuple: %v", err)
	}
	defer competitor.Close()

	registry := NewPortRegistry()
	if _, err := registry.AcquireTCP(context.Background(), "late-owner", address); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("late acquire error = %v, want EADDRINUSE", err)
	}
}

func TestProcessLockBlocksConcurrentInstallerProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.lock")
	lock, err := AcquireProcessLock(path)
	if err != nil {
		t.Fatalf("acquire parent process lock: %v", err)
	}
	defer lock.Close()

	command := exec.Command(os.Args[0], "-test.run=^TestProcessLockHelper$")
	command.Env = append(os.Environ(), "ANTINAT_P02_LOCK_HELPER="+path)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run competing process: %v\n%s", err, output)
	}
	if got := strings.TrimSpace(string(output)); !strings.Contains(got, "LOCK_BLOCKED") {
		t.Fatalf("competing process output = %q, want LOCK_BLOCKED", got)
	}
}

func TestProcessLockHelper(t *testing.T) {
	path := os.Getenv("ANTINAT_P02_LOCK_HELPER")
	if path == "" {
		t.Skip("subprocess helper")
	}
	lock, err := AcquireProcessLock(path)
	if errors.Is(err, ErrInstanceLocked) {
		fmt.Println("LOCK_BLOCKED")
		return
	}
	if err != nil {
		t.Fatalf("acquire helper process lock: %v", err)
	}
	defer lock.Close()
	fmt.Println("LOCK_ACQUIRED")
}

func TestPortRegistryConcurrentAcquireHasSingleOwner(t *testing.T) {
	probe, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("reserve tuple for test: %v", err)
	}
	address := probe.Addr().(*net.TCPAddr)
	probe.Close()

	registry := NewPortRegistry()
	const contenders = 16
	type acquireResult struct {
		lease *TCPLease
		err   error
	}
	start := make(chan struct{})
	results := make(chan acquireResult, contenders)
	for contender := 0; contender < contenders; contender++ {
		go func(owner int) {
			<-start
			lease, err := registry.AcquireTCP(context.Background(), fmt.Sprintf("owner-%d", owner), address)
			results <- acquireResult{lease: lease, err: err}
		}(contender)
	}
	close(start)

	var winner *TCPLease
	for contender := 0; contender < contenders; contender++ {
		result := <-results
		if result.err == nil {
			if winner != nil {
				t.Fatal("more than one concurrent acquire succeeded")
			}
			winner = result.lease
			continue
		}
		if !errors.Is(result.err, ErrTupleOverlap) {
			t.Fatalf("losing acquire error = %v, want ErrTupleOverlap", result.err)
		}
	}
	if winner == nil {
		t.Fatal("no concurrent acquire succeeded")
	}
	defer winner.Release()
}

func TestSecondProcessCanJoinReuseGroupWithoutInstanceLock(t *testing.T) {
	fixture, err := OpenTCPSharedPort(context.Background(), net.ParseIP("127.0.0.1"), nil)
	if err != nil {
		t.Fatalf("open parent reuse listener: %v", err)
	}
	defer fixture.Close()

	command := exec.Command(os.Args[0], "-test.run=^TestReuseGroupHelper$")
	command.Env = append(os.Environ(), "ANTINAT_P02_REUSE_ADDR="+fixture.Listener.Addr().String())
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run reuse-group process: %v\n%s", err, output)
	}
	if got := strings.TrimSpace(string(output)); !strings.Contains(got, "REUSE_GROUP_JOINED") {
		t.Fatalf("reuse-group process output = %q, want REUSE_GROUP_JOINED", got)
	}
}

func TestReuseGroupHelper(t *testing.T) {
	addressText := os.Getenv("ANTINAT_P02_REUSE_ADDR")
	if addressText == "" {
		t.Skip("subprocess helper")
	}
	address, err := net.ResolveTCPAddr("tcp4", addressText)
	if err != nil {
		t.Fatalf("resolve reuse address: %v", err)
	}
	fixture, err := OpenTCPSharedPortAt(context.Background(), address, nil)
	if err != nil {
		t.Fatalf("join reuse group: %v", err)
	}
	defer fixture.Close()
	fmt.Println("REUSE_GROUP_JOINED")
}
