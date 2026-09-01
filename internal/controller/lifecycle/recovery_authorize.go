// P14 repair-1 H2a: the durable operator finalize/reauthorize path that ADVANCES
// a restore operation out of RESTORE_RECONCILIATION. Before this function was
// wired, store.AdvanceRestorePhase had no caller, so IsRestoreReconciling()
// stayed true forever and EnforceCleanupOnlyEnqueue refused every automatic
// desired/delete/rotation dispatch for every node indefinitely. FinalizeRestore
// is the global finalize; per-node quarantine still requires ReauthorizeNode.
package lifecycle

import (
	"context"
	"errors"
	"fmt"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
)

// ErrRestorePhaseRefuses is the fail-closed restore-phase transition error.
var ErrRestorePhaseRefuses = errors.New("lifecycle: restore phase refused")

// FinalizeRestore advances a durable restore operation from its reconciliation
// phase to AUTHORIZED. While the restore op is not AUTHORIZED the controller is
// in recovery quarantine: no automatic desired/delete/probe/rotation dispatch
// may flow. This is the operator's explicit finalize gate; it does NOT by itself
// clear the per-node quarantine flag, so a node resumes normal dispatch only
// after BOTH this global finalize AND store.ReauthorizeNode(nodeID).
func FinalizeRestore(ctx context.Context, s *store.Store, operationID string) (store.RestoreOperation, error) {
	op, err := s.GetRestoreOperation(operationID)
	if err != nil {
		return store.RestoreOperation{}, err
	}
	if op.Phase == "AUTHORIZED" {
		// Idempotent finalize: already authorized is success.
		return op, nil
	}
	if err := s.AdvanceRestorePhase(operationID, "AUTHORIZED"); err != nil {
		return store.RestoreOperation{}, err
	}
	op.Phase = "AUTHORIZED"
	return op, nil
}

// ReauthorizeNode is the per-node gate exposed at the lifecycle layer: it clears
// a single node's restore quarantine so normal dispatch can resume for it after
// the global FinalizeRestore. It is a thin wrapper over store.ReauthorizeNode so
// the API layer has a lifecycle-owned surface.
func ReauthorizeNode(ctx context.Context, s *store.Store, nodeID string) error {
	if err := s.ReauthorizeNode(nodeID); err != nil {
		return fmt.Errorf("lifecycle: reauthorize node: %w", err)
	}
	return nil
}
