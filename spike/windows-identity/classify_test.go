package windowsidentity

import "testing"

// RED-then-GREEN coverage for the Windows-identity capability classification.
// The pre-repair probe could report SUPPORTED_WITH_LIMITS after DPAPI/ACL/
// service-SID checks passed while Defender firewall ownership remained
// UNVALIDATED. The classification now fails closed: the overall capability
// must not be claimed supported until managed/manual Defender ownership is
// validated.

func TestClassifyRequiresValidatedDefenderOwnership(t *testing.T) {
	// DPAPI + protected ACL + service SID all pass, but Defender ownership is
	// still UNVALIDATED: the overall capability must NOT be supported.
	if got := ClassifyCapability(true, true, "S-1-5-80-123", "UNVALIDATED"); got == "SUPPORTED_WITH_LIMITS" {
		t.Fatalf("capability %q claimed with UNVALIDATED Defender ownership; want fail closed", got)
	}
}

func TestClassifySupportedOnlyWithFullEvidence(t *testing.T) {
	if got := ClassifyCapability(true, true, "S-1-5-80-123", "VALIDATED"); got != "SUPPORTED_WITH_LIMITS" {
		t.Fatalf("fully validated identity = %q, want SUPPORTED_WITH_LIMITS", got)
	}
	if got := ClassifyCapability(false, true, "S-1-5-80-123", "VALIDATED"); got != "UNSUPPORTED" {
		t.Fatalf("missing DPAPI = %q, want UNSUPPORTED", got)
	}
	if got := ClassifyCapability(true, true, "", "VALIDATED"); got != "UNSUPPORTED" {
		t.Fatalf("missing service SID = %q, want UNSUPPORTED", got)
	}
}
