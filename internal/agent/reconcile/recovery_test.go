// P14 Story 5 (reconcile side): RecoveryDeferred decision for the restore
// quarantine / terminal-marker one-way boundaries.
package reconcile

import (
	"testing"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
)

// TestRecoveryDeferredBoundaries covers the three outcomes: terminal marker
// deferral, quarantine deferral, and normal recovery allowed.
func TestRecoveryDeferredBoundaries(t *testing.T) {
	dir := t.TempDir()

	// Normal: no marker, no quarantine -> recovery allowed.
	deferred, reason, err := RecoveryDeferred(dir, localstate.MarkerActive)
	if err != nil {
		t.Fatal(err)
	}
	if deferred || reason != RecoveryAllowed {
		t.Fatalf("normal state deferred=%v reason=%q", deferred, reason)
	}

	// Terminal marker is the highest-priority boundary.
	if err := localstate.WriteMarker(dir, localstate.MarkerDecommissioned); err != nil {
		t.Fatal(err)
	}
	deferred, reason, err = RecoveryDeferred(dir, localstate.MarkerDecommissioned)
	if err != nil {
		t.Fatal(err)
	}
	if !deferred || reason != DeferredByTerminalMarker {
		t.Fatalf("terminal state deferred=%v reason=%q", deferred, reason)
	}

	// Quarantine alone defers recovery.
	dir2 := t.TempDir()
	if err := localstate.WriteRecoveryQuarantine(dir2); err != nil {
		t.Fatal(err)
	}
	deferred, reason, err = RecoveryDeferred(dir2, localstate.MarkerActive)
	if err != nil {
		t.Fatal(err)
	}
	if !deferred || reason != DeferredByRecoveryQuarantine {
		t.Fatalf("quarantine state deferred=%v reason=%q", deferred, reason)
	}
}
