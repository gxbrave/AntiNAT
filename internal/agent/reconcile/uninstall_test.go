// P14 Story 6: agent uninstall notice — online bounded receipt vs offline
// UNKNOWN, and the terminal marker always prevents LKG recovery afterward.
package reconcile

import (
	"context"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// TestUninstallNoticeOnlineQueuesBoundedReceipt: an online agent queues the
// notice for a durable controller receipt (bounded best-effort).
func TestUninstallNoticeOnlineQueuesBoundedReceipt(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	dir := t.TempDir()

	res, err := NotifyUninstall(context.Background(), st, dir, "unst-op-1", func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "QUEUED" || !res.Online {
		t.Fatalf("result = %+v, want QUEUED online", res)
	}
	if !st.OutboxContains("unst-op-1") {
		t.Fatal("uninstall notice not queued to the outbox for a durable receipt")
	}
	notice, found, err := st.UninstallNoticeStatus("unst-op-1")
	if err != nil || !found {
		t.Fatalf("durable notice missing found=%v err=%v", found, err)
	}
	if notice.Connectivity != true {
		t.Fatalf("notice connectivity = %v", notice.Connectivity)
	}
}

// TestUninstallNoticeOfflineIsUnknown: an offline agent records UNKNOWN and
// never claims a delivery.
func TestUninstallNoticeOfflineIsUnknown(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	dir := t.TempDir()

	res, err := NotifyUninstall(context.Background(), st, dir, "unst-op-2", func() bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "UNKNOWN" || res.Online {
		t.Fatalf("result = %+v, want UNKNOWN offline", res)
	}
	if st.OutboxContains("unst-op-2") {
		t.Fatal("offline uninstall must not queue a delivery it cannot send")
	}
	notice, found, _ := st.UninstallNoticeStatus("unst-op-2")
	if !found || notice.Status != "UNKNOWN" {
		t.Fatalf("durable notice = %+v found=%v", notice, found)
	}
}

// TestUninstallNoticeTerminalMarkerAlwaysPreventsLKGRecovery: after a
// DECOMMISSIONED marker the uninstall notice still records, but the terminal
// marker is the one-way authority — reconcile refuses and the applied LKG can
// never be recovered.
func TestUninstallNoticeTerminalMarkerAlwaysPreventsLKGRecovery(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	dir := t.TempDir()
	if err := localstate.WriteMarker(dir, localstate.MarkerDecommissioning); err != nil {
		t.Fatal(err)
	}
	if err := localstate.WriteMarker(dir, localstate.MarkerDecommissioned); err != nil {
		t.Fatal(err)
	}

	if _, err := NotifyUninstall(context.Background(), st, dir, "unst-op-3", func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	marker, err := localstate.LoadMarker(dir)
	if err != nil {
		t.Fatal(err)
	}
	if marker != localstate.MarkerDecommissioned {
		t.Fatalf("marker changed to %q during uninstall", marker)
	}
	// Reconcile on a DECOMMISSIONED agent must refuse every LKG restore.
	reconciler := New(st, localstate.NewLatch(), marker, applyFakeHook, nil)
	desired := protocol.DesiredState{NodeID: "node-1"}
	if _, err := reconciler.ReconcileOnce(context.Background(), desired, 0, ""); err == nil {
		t.Fatal("reconcile succeeded on a DECOMMISSIONED agent")
	}
}
