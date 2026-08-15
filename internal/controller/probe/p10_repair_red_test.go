package probe

import (
	"context"
	"testing"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

func TestArmRequiresNonEmptyCurrentActivation(t *testing.T) {
	env := newTestEnv(t, false)
	if err := env.store.CreateNode(store.Node{ID: "n1", Name: "n1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.CreateForward(store.Forward{
		ID: "f-current", NodeID: "n1", Name: "current", Protocol: "tcp",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.manager.Arm(context.Background(), "n1", "f-current", "act-any", "198.51.100.7:8080"); err == nil {
		t.Fatal("arm accepted a forward without a current activation")
	}
}
