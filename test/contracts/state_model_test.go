package contracts

import (
	"path/filepath"
	"testing"
)

// stateFixture is the frozen fixture schema for state/lifecycle vectors under
// test/contracts/testdata/state-model/.
//
// Kinds:
//   - "transition": asserts a single FSM transition is allowed or rejected.
//   - "snapshot":   asserts a complete orthogonal activation-state snapshot is
//     valid or invalid.
//   - "publication": asserts publication-invariant truth rules.
//   - "applied_forward": asserts an AppliedForwardState record is valid.
type stateFixture struct {
	Schema   string            `json:"schema"`
	VectorID string            `json:"vector_id"`
	Kind     string            `json:"kind"`
	Expect   string            `json:"expect"`
	FSM      string            `json:"fsm,omitempty"`
	From     string            `json:"from,omitempty"`
	To       string            `json:"to,omitempty"`
	Snapshot map[string]string `json:"snapshot,omitempty"`
	Pub      struct {
		Publication string `json:"publication_state"`
		WAN         string `json:"wan_reachability_state"`
		ReturnPath  string `json:"return_path_state"`
	} `json:"publication,omitempty"`
	Applied appliedForwardState `json:"applied_forward,omitempty"`
}

func TestStateModelGoldenVectors(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "test", "contracts", "testdata", "state-model")
	files := walkJSONFiles(t, dir)
	if len(files) == 0 {
		t.Fatalf("no state-model fixtures found under %s", dir)
	}
	for _, path := range files {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			var fx stateFixture
			loadFixtureJSON(t, path, &fx)
			if fx.Schema != "antinat.contracts/state-model/v1" {
				t.Fatalf("unexpected schema %q", fx.Schema)
			}
			switch fx.Kind {
			case "transition":
				validateTransitionFixture(t, fx)
			case "snapshot":
				validateSnapshotFixture(t, fx)
			case "publication":
				validatePublicationFixture(t, fx)
			case "applied_forward":
				validateAppliedForwardFixture(t, fx)
			default:
				t.Fatalf("unknown state fixture kind %q", fx.Kind)
			}
		})
	}
}

func validateTransitionFixture(t *testing.T, fx stateFixture) {
	t.Helper()
	err := validateFSMTransition(fx.FSM, fx.From, fx.To)
	switch fx.Expect {
	case "allowed":
		if err != nil {
			t.Fatalf("allowed transition %s %s->%s rejected: %v", fx.FSM, fx.From, fx.To, err)
		}
	case "rejected":
		if err == nil {
			t.Fatalf("illegal transition %s %s->%s accepted", fx.FSM, fx.From, fx.To)
		}
	default:
		t.Fatalf("transition expect must be allowed or rejected, got %q", fx.Expect)
	}
}

func validateSnapshotFixture(t *testing.T, fx stateFixture) {
	t.Helper()
	err := validActivationSnapshot(fx.Snapshot)
	switch fx.Expect {
	case "valid":
		if err != nil {
			t.Fatalf("valid snapshot rejected: %v", err)
		}
	case "invalid":
		if err == nil {
			t.Fatalf("invalid snapshot accepted")
		}
	default:
		t.Fatalf("snapshot expect must be valid or invalid, got %q", fx.Expect)
	}
}

func validatePublicationFixture(t *testing.T, fx stateFixture) {
	t.Helper()
	err := publicationInvariants(fx.Pub.Publication, fx.Pub.WAN, fx.Pub.ReturnPath)
	switch fx.Expect {
	case "valid":
		if err != nil {
			t.Fatalf("valid publication rejected: %v", err)
		}
	case "invalid":
		if err == nil {
			t.Fatalf("invalid publication accepted")
		}
	default:
		t.Fatalf("publication expect must be valid or invalid, got %q", fx.Expect)
	}
}

func validateAppliedForwardFixture(t *testing.T, fx stateFixture) {
	t.Helper()
	err := validAppliedForwardState(fx.Applied)
	switch fx.Expect {
	case "valid":
		if err != nil {
			t.Fatalf("valid applied_forward rejected: %v", err)
		}
	case "invalid":
		if err == nil {
			t.Fatalf("invalid applied_forward accepted")
		}
	default:
		t.Fatalf("applied_forward expect must be valid or invalid, got %q", fx.Expect)
	}
}
