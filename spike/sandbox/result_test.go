package sandbox

import "testing"

func TestUnsupportedResultReportsEveryRequiredGate(t *testing.T) {
	result := unsupportedResult("setup unavailable")
	if result.Supported || result.Fallback != "webhook-only" {
		t.Fatalf("unsupported result = %+v", result)
	}
	for _, name := range requiredGateNames {
		gate, ok := result.Gates[name]
		if !ok {
			t.Errorf("required gate %q missing", name)
			continue
		}
		if gate.Pass || gate.Detail != "setup unavailable" {
			t.Errorf("gate %q = %+v", name, gate)
		}
	}
}
