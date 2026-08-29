package controller

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/security"
)

type deletionWatcherFixture struct {
	app        *App
	nodeID     string
	forwardID  string
	deletionID string
	commandID  string
	resultID   string
}

func deletionResultMessageID(operationID, messageType string) string {
	id := security.MessageID(operationID, messageType)
	return hex.EncodeToString(id[:])
}

func newDeletionWatcherFixture(t *testing.T, suffix string) *deletionWatcherFixture {
	t.Helper()
	app, err := New(Config{
		StorePath: filepath.Join(t.TempDir(), "controller.db"),
		KeyDir:    t.TempDir(),
		Clock:     time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Shutdown(nil) })

	f := &deletionWatcherFixture{
		app:        app,
		nodeID:     "r16-delete-node-" + suffix,
		forwardID:  "r16-delete-forward-" + suffix,
		deletionID: "r16-delete-operation-" + suffix,
	}
	if err := app.Store().CreateNode(store.Node{ID: f.nodeID, Name: f.nodeID}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Store().CreateForward(store.Forward{
		ID: f.forwardID, NodeID: f.nodeID, Name: f.forwardID, Protocol: "tcp",
		CurrentActivationID: "r16-delete-activation-" + suffix, Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.Store().ApplyForwardDelete(store.ForwardDeletionOperation{
		ID: f.deletionID, ForwardID: f.forwardID, Status: "PENDING", DesiredRevision: 1,
	}, store.ControlOutboxItem{
		OperationID: f.deletionID, MessageType: "desired", NodeID: f.nodeID,
		SemanticPayload: `{}`, State: "PENDING",
	}); err != nil {
		t.Fatal(err)
	}
	f.commandID = deletionResultMessageID(f.deletionID, "desired")
	// The deletion watcher consumes the dedicated controller-operation-complete
	// result, not the ordinary generic command result.
	f.resultID = deletionResultMessageID(f.deletionID, "operation_complete")
	return f
}

func (f *deletionWatcherFixture) record(payload string) error {
	_, err := f.app.Store().RecordControlInbox(store.ControlInboxItem{
		MessageID: f.resultID, NodeID: f.nodeID, MessageType: "operation_complete",
		OperationID: f.deletionID, SemanticPayload: payload,
	})
	return err
}

func (f *deletionWatcherFixture) validPayload() string {
	return fmt.Sprintf(`{"forward_id":%q,"deletion_operation_id":%q,"deleted":true}`,
		f.forwardID, f.deletionID)
}

func (f *deletionWatcherFixture) state(t *testing.T) string {
	t.Helper()
	state, err := f.app.Store().ControlInboxState(f.resultID)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestR16DeletionWatcherTerminalizesPermanentIdentityFailure(t *testing.T) {
	f := newDeletionWatcherFixture(t, "mismatch")
	if err := f.record(fmt.Sprintf(`{"forward_id":%q,"deletion_operation_id":%q,"deleted":true}`,
		f.forwardID, "wrong-delete")); err != nil {
		t.Fatal(err)
	}

	f.app.completeFinishedDeletions()
	if got := f.state(t); got != store.ControlInboxNacked {
		t.Fatalf("permanent identity poison state = %q, want NACKED", got)
	}
	deletion, err := f.app.Store().GetForwardDeletionOperation(f.deletionID)
	if err != nil {
		t.Fatal(err)
	}
	if deletion.Status != "PENDING" {
		t.Fatalf("poison result changed deletion status to %q", deletion.Status)
	}
}

func TestR16DeletionWatcherNACKsMalformedResult(t *testing.T) {
	f := newDeletionWatcherFixture(t, "malformed")
	if err := f.record(fmt.Sprintf(`{"forward_id":%q,"deleted":true}`, f.forwardID)); err != nil {
		t.Fatal(err)
	}

	f.app.completeFinishedDeletions()
	if got := f.state(t); got != store.ControlInboxNacked {
		t.Fatalf("malformed result state = %q, want NACKED", got)
	}
}

func TestR16DeletionWatcherNACKsWrongForward(t *testing.T) {
	f := newDeletionWatcherFixture(t, "forward-mismatch")
	if err := f.record(fmt.Sprintf(`{"forward_id":%q,"deletion_operation_id":%q,"deleted":true}`,
		"wrong-forward", f.deletionID)); err != nil {
		t.Fatal(err)
	}

	f.app.completeFinishedDeletions()
	if got := f.state(t); got != store.ControlInboxNacked {
		t.Fatalf("wrong-forward result state = %q, want NACKED", got)
	}
}

func TestR16DeletionWatcherNACKsMissingForwardIdentity(t *testing.T) {
	f := newDeletionWatcherFixture(t, "missing-forward")
	if err := f.record(f.validPayload()); err != nil {
		t.Fatal(err)
	}
	if err := f.app.Store().DeleteForwardRow(f.forwardID); err != nil {
		t.Fatal(err)
	}

	f.app.completeFinishedDeletions()
	if got := f.state(t); got != store.ControlInboxNacked {
		t.Fatalf("missing-forward result state = %q, want NACKED", got)
	}
	deletion, err := f.app.Store().GetForwardDeletionOperation(f.deletionID)
	if err != nil {
		t.Fatal(err)
	}
	if deletion.Status != "PENDING" {
		t.Fatalf("missing-forward result changed deletion status to %q", deletion.Status)
	}
}

func openDeletionRawDB(t *testing.T, f *deletionWatcherFixture) *sql.DB {
	t.Helper()
	rawDB, err := sql.Open("sqlite", "file:"+f.app.Store().Path()+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(FULL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rawDB.Close() })
	return rawDB
}

func TestR16DeletionWatcherLeavesTransientCompletionFailureRetryable(t *testing.T) {
	f := newDeletionWatcherFixture(t, "transient")
	if err := f.record(f.validPayload()); err != nil {
		t.Fatal(err)
	}
	rawDB := openDeletionRawDB(t, f)
	if _, err := rawDB.Exec(`CREATE TRIGGER r16_delete_completion_failure
		BEFORE UPDATE OF status ON forward_deletion_operations
		BEGIN SELECT RAISE(ABORT, 'injected deletion completion failure'); END`); err != nil {
		t.Fatal(err)
	}
	f.app.completeFinishedDeletions()
	if got := f.state(t); got != store.ControlInboxReceived {
		t.Fatalf("transient completion state = %q, want RECEIVED", got)
	}
	if _, err := rawDB.Exec(`DROP TRIGGER r16_delete_completion_failure`); err != nil {
		t.Fatal(err)
	}

	f.app.completeFinishedDeletions()
	if got := f.state(t); got != store.ControlInboxProcessed {
		t.Fatalf("retried completion state = %q, want PROCESSED", got)
	}
	deletion, err := f.app.Store().GetForwardDeletionOperation(f.deletionID)
	if err != nil {
		t.Fatal(err)
	}
	if deletion.Status != "COMPLETED" {
		t.Fatalf("retried completion status = %q, want COMPLETED", deletion.Status)
	}
}

func TestR16DeletionWatcherLeavesPermanentDispositionRetryable(t *testing.T) {
	f := newDeletionWatcherFixture(t, "nack-failure")
	if err := f.record(fmt.Sprintf(`{"forward_id":%q,"deleted":true}`, f.forwardID)); err != nil {
		t.Fatal(err)
	}
	rawDB := openDeletionRawDB(t, f)
	if _, err := rawDB.Exec(`CREATE TRIGGER r16_delete_nack_failure
		BEFORE UPDATE OF state ON control_inbox WHEN NEW.state = 'NACKED'
		BEGIN SELECT RAISE(ABORT, 'injected deletion NACK failure'); END`); err != nil {
		t.Fatal(err)
	}
	f.app.completeFinishedDeletions()
	if got := f.state(t); got != store.ControlInboxReceived {
		t.Fatalf("failed NACK state = %q, want RECEIVED", got)
	}
	if _, err := rawDB.Exec(`DROP TRIGGER r16_delete_nack_failure`); err != nil {
		t.Fatal(err)
	}

	f.app.completeFinishedDeletions()
	if got := f.state(t); got != store.ControlInboxNacked {
		t.Fatalf("retried NACK state = %q, want NACKED", got)
	}
}
