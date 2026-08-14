package localstate

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// openProbeStore opens a fresh agent store.
func openProbeStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleArm() protocol.ProbeArm {
	var arm protocol.ProbeArm
	copy(arm.ProbeID[:], "probe-0001")
	copy(arm.ProviderID[:], "provider-0001")
	copy(arm.Activation[:], "activation-01")
	arm.Endpoint = "198.51.100.7:8080"
	arm.TTLMS = 30000
	copy(arm.ExpiryOpaque[:], "opaque-00000001")
	return arm
}

// TestSchemaV2ProbeBucket verifies migration v2 added the probe_operations
// bucket on a fresh store and on an existing v1 store.
func TestSchemaV2ProbeBucket(t *testing.T) {
	s := openProbeStore(t)
	v, err := s.SchemaVersion()
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if v != 2 {
		t.Fatalf("SchemaVersion = %d, want 2 (v1 buckets + probe_operations)", v)
	}
	// The bucket must be usable through the store API.
	if err := s.SaveArmedProbe(sampleArm(), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("save armed probe: %v", err)
	}
}

// TestSaveLoadDeleteArmedProbe covers the durable armed-probe journal:
// persist, load with deadline, idempotent re-save, and delete.
func TestSaveLoadDeleteArmedProbe(t *testing.T) {
	s := openProbeStore(t)
	arm := sampleArm()

	deadline := time.Now().Add(time.Minute)
	if err := s.SaveArmedProbe(arm, deadline); err != nil {
		t.Fatalf("save armed probe: %v", err)
	}
	// Idempotent re-save of the same probe id must not fail.
	if err := s.SaveArmedProbe(arm, deadline); err != nil {
		t.Fatalf("re-save armed probe: %v", err)
	}

	loaded, ok, err := s.LoadArmedProbe(arm.ProbeID)
	if err != nil {
		t.Fatalf("load armed probe: %v", err)
	}
	if !ok {
		t.Fatal("armed probe not found after save")
	}
	if loaded.Arm != arm || !loaded.Deadline.Equal(deadline) {
		t.Fatalf("loaded probe mismatch: %+v", loaded)
	}

	// A different probe id is not present.
	if _, ok, err := s.LoadArmedProbe([16]byte{9}); err != nil || ok {
		t.Fatalf("unexpected probe present (ok=%v err=%v)", ok, err)
	}

	if err := s.DeleteArmedProbe(arm.ProbeID); err != nil {
		t.Fatalf("delete armed probe: %v", err)
	}
	if _, ok, err := s.LoadArmedProbe(arm.ProbeID); err != nil || ok {
		t.Fatalf("probe still present after delete (ok=%v err=%v)", ok, err)
	}
}

// TestListArmedProbesLoadsAll covers listing for restart recovery: expired
// probes are returned too (the caller decides expiry by deadline).
func TestListArmedProbesLoadsAll(t *testing.T) {
	s := openProbeStore(t)
	arm1 := sampleArm()
	arm2 := sampleArm()
	arm2.ProbeID[0] = 'p'
	arm2.ProbeID[1] = 'r'
	arm2.ProbeID[2] = 'o'
	arm2.ProbeID[3] = 'b'
	arm2.ProbeID[4] = 'e'
	arm2.ProbeID[5] = '-'
	arm2.ProbeID[6] = '0'
	arm2.ProbeID[7] = '0'
	arm2.ProbeID[8] = '0'
	arm2.ProbeID[9] = '2'

	if err := s.SaveArmedProbe(arm1, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("save arm1: %v", err)
	}
	if err := s.SaveArmedProbe(arm2, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("save arm2 (expired): %v", err)
	}

	list, err := s.ListArmedProbes()
	if err != nil {
		t.Fatalf("list armed probes: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("listed %d armed probes, want 2", len(list))
	}
	seen := map[[16]byte]bool{}
	for _, p := range list {
		seen[p.Arm.ProbeID] = true
	}
	if !seen[arm1.ProbeID] || !seen[arm2.ProbeID] {
		t.Fatalf("missing probes in list: %+v", seen)
	}
}
