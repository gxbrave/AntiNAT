package web

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// seedHomeFixture builds the minimal store fixture used by the home tests:
// two nodes (online/offline) and forwards with real activation snapshots.
func seedHomeFixture(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "home.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	for _, n := range []store.Node{
		{ID: "n-on", Name: "on", ControlState: "ONLINE", Revision: 1},
		{ID: "n-off", Name: "off", ControlState: "OFFLINE", Revision: 1},
	} {
		if err := st.CreateNode(n); err != nil {
			t.Fatalf("create node %s: %v", n.ID, err)
		}
	}

	type fx struct {
		id         string
		nodeID     string
		activation protocol.ActivationStates
	}
	base := protocol.ActivationStates{
		ControlState: "ONLINE", ListenerState: "READY", MappingState: "PUBLIC_CANDIDATE",
		KeepaliveState: "HEALTHY", WanReachabilityState: "PROBING", ReturnPathState: "NOT_TESTED",
		TargetHealthState: "PASS", PublicationState: "NONE", DataPlaneState: "READY",
	}
	verified := base
	verified.WanReachabilityState = "OPEN_FROM_VANTAGE"
	verified.ReturnPathState = "VERIFIED"
	verified.PublicationState = "PUBLISHED_VERIFIED"

	unverified := base
	unverified.WanReachabilityState = "NO_INDEPENDENT_VANTAGE"
	unverified.PublicationState = "PUBLISHED_UNVERIFIED"

	stale := verified
	stale.PublicationState = "STALE"

	broken := unverified
	broken.MappingState = "LOST"
	broken.TargetHealthState = "FAIL"

	fixtures := []fx{
		{id: "f-ver", nodeID: "n-on", activation: verified},
		{id: "f-un", nodeID: "n-on", activation: unverified},
		{id: "f-st", nodeID: "n-on", activation: stale},
		{id: "f-off", nodeID: "n-off", activation: unverified},
		{id: "f-bad", nodeID: "n-on", activation: broken},
	}
	for _, fx := range fixtures {
		act := protocol.ActivationID(fx.id, 1)
		actHex := hexString(act[:])
		if _, err := st.CreateForward(store.Forward{ID: fx.id, NodeID: fx.nodeID, Name: fx.id, Protocol: "tcp", CurrentActivationID: actHex, Revision: 1}); err != nil {
			t.Fatalf("create forward %s: %v", fx.id, err)
		}
		raw, _ := json.Marshal(fx.activation)
		if err := st.SetForwardRuntimeStatus(fx.id, actHex, 1, string(raw)); err != nil {
			t.Fatalf("set status %s: %v", fx.id, err)
		}
	}
	return st
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0x0f]
	}
	return string(out)
}

func newTestUI(t *testing.T, st *store.Store) *uiHandlers {
	t.Helper()
	i18n, err := newI18N()
	if err != nil {
		t.Fatalf("i18n: %v", err)
	}
	return &uiHandlers{store: st, i18n: i18n}
}

func TestHomeStatusDerivationOverRealSnapshots(t *testing.T) {
	st := seedHomeFixture(t)
	h := newTestUI(t, st)

	cat := store.NavigationCategory{ID: "c", Name: "Work", OrderIndex: 0}
	if _, err := st.CreateNavigationCategory(cat); err != nil {
		t.Fatalf("category: %v", err)
	}
	want := map[string]string{
		"f-ver": "verified",
		"f-un":  "unverified",
		"f-st":  "stale",
		"f-off": "offline",
		"f-bad": "failed",
	}
	order := 0
	for id, status := range want {
		item := store.NavigationItem{ID: "i-" + id, Name: id, CategoryID: "c", ForwardID: id, OrderIndex: order}
		order++
		got, ok := h.resolveHomeItem("zh", item)
		if !ok {
			t.Fatalf("resolveHomeItem(%s) not ok", id)
		}
		if got.Status != status {
			t.Errorf("forward %s: status = %q, want %q (label %q)", id, got.Status, status, got.StatusLabel)
		}
		// Durable labels must never be empty (text evidence, not color-only).
		if got.StatusLabel == "" {
			t.Errorf("forward %s: empty status label", id)
		}
		if got.RiskNote == "" && status != "verified" {
			t.Errorf("forward %s: risky status must carry a risk note", id)
		}
		if got.Clickable != (status == "verified") {
			t.Errorf("forward %s: clickable = %v, want %v", id, got.Clickable, status == "verified")
		}
	}
}

func TestHomeCategoryAssemblyWithNoRuntimeEvidence(t *testing.T) {
	st := seedHomeFixture(t)
	h := newTestUI(t, st)
	if _, err := st.CreateNavigationCategory(store.NavigationCategory{ID: "c", Name: "Work", OrderIndex: 0}); err != nil {
		t.Fatal(err)
	}
	// A forward with no runtime snapshot yet must render as unknown, not crash.
	if err := st.CreateNode(store.Node{ID: "n-late", Name: "late", ControlState: "ONLINE", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateForward(store.Forward{ID: "f-late", NodeID: "n-late", Name: "late", Protocol: "tcp", CurrentActivationID: "act-late", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateNavigationItem(store.NavigationItem{ID: "i-late", Name: "late", CategoryID: "c", ForwardID: "f-late", OrderIndex: 9}); err != nil {
		t.Fatalf("late item: %v", err)
	}
	cats, err := h.buildHomeCategories("zh")
	if err != nil {
		t.Fatalf("buildHomeCategories: %v", err)
	}
	if len(cats) != 1 {
		t.Fatalf("categories = %d, want 1", len(cats))
	}
	if len(cats[0].Items) != 1 {
		t.Fatalf("items = %d, want 1", len(cats[0].Items))
	}
	if got := cats[0].Items[0].Status; got != "unknown" {
		t.Errorf("no-evidence forward status = %q, want unknown", got)
	}
}
