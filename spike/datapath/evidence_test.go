package datapath

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEligibilityLabelNeverClaimsRuntimeSpliceBytes(t *testing.T) {
	evidence := Classify(true)
	if evidence.DataPath != "go_tcp_copy_splice_eligible" {
		t.Fatalf("data path = %q", evidence.DataPath)
	}
	if evidence.ZeroCopyEvidence != "eligible" {
		t.Fatalf("zero-copy evidence = %q, want eligible", evidence.ZeroCopyEvidence)
	}
	if evidence.PessimisticFallbackBytesPerConnection != 64*1024 {
		t.Fatalf("fallback budget = %d, want 65536", evidence.PessimisticFallbackBytesPerConnection)
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"zero_copy_active", "splice_bytes", "buffered_fallback_bytes"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("eligibility evidence contains forbidden runtime claim %q: %s", forbidden, encoded)
		}
	}
}
