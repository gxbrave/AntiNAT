package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
	_ "modernc.org/sqlite"
)

// The lifecycle lock must cover the whole Close wait. Otherwise Start can
// install a fresh sweeper after Close has cancelled the old one, leaving Close
// waiting on a WaitGroup that the new sweeper never joins.
func TestR16QManagerCloseSerializesConcurrentStart(t *testing.T) {
	env := newTestEnv(t, false)
	mgr := env.manager
	if err := mgr.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Keep Close in its join phase while a concurrent Start is attempted. This
	// is a test-only waiter; production work is already fenced by m.mu.
	mgr.mu.Lock()
	mgr.workWG.Add(1)
	mgr.mu.Unlock()

	closeDone := make(chan error, 1)
	go func() { closeDone <- mgr.Close() }()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mgr.mu.Lock()
		closing := mgr.cancel == nil && mgr.closed
		mgr.mu.Unlock()
		if closing {
			break
		}
		time.Sleep(time.Millisecond)
	}
	mgr.mu.Lock()
	closing := mgr.cancel == nil && mgr.closed
	mgr.mu.Unlock()
	if !closing {
		t.Fatal("Close did not reach its cancellation/join phase")
	}

	startDone := make(chan error, 1)
	startCtx, cancelStart := context.WithCancel(context.Background())
	defer cancelStart()
	go func() { startDone <- mgr.Start(startCtx) }()

	select {
	case err := <-startDone:
		// The old implementation returns here and leaks a new sweeper into the
		// in-progress Close. Finish cleanup below so the test never strand a
		// goroutine, then report the lifecycle violation.
		if err == nil {
			cancelStart()
		}
		mgr.workWG.Done()
		if closeErr := <-closeDone; closeErr != nil {
			t.Fatalf("Close: %v", closeErr)
		}
		if err == nil {
			_ = mgr.Close()
		}
		t.Fatalf("concurrent Start returned before Close completed: %v", err)
	case <-time.After(100 * time.Millisecond):
		// Expected: Start is serialized behind Close.
	}

	mgr.workWG.Done()
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if err := <-startDone; err != nil {
		t.Fatalf("Start after Close: %v", err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatal(err)
	}
}

// A revision advance may retain the same activation identifier. Arm must not
// reuse the runtime mirror observed at the previous generation.
func TestR16QArmRejectsSameActivationAfterForwardRevisionAdvance(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	if err := env.store.CASForwardActivation("f1", 1, "act-1"); err != nil {
		t.Fatal(err)
	}

	if _, err := env.manager.Arm(context.Background(), "n1", "f1", "act-1", "198.51.100.7:8080"); !errors.Is(err, store.ErrCASConflict) {
		t.Fatalf("Arm after same-activation generation advance = %v, want stale-generation CAS conflict", err)
	}
	runtime, err := env.store.GetForwardRuntimeStatus("f1")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.ActivationID != "act-1" || !runtime.GenerationBound || runtime.Generation != 1 {
		t.Fatalf("stale runtime mirror changed activation identity: %+v", runtime)
	}
	if runtime.SnapshotJSON != r16RuntimeSnapshot {
		t.Fatalf("same-activation revision advance changed runtime axes: %s", runtime.SnapshotJSON)
	}

	if err := env.store.SetForwardRuntimeStatus("f1", "act-1", 2, r16RuntimeSnapshot); err != nil {
		t.Fatalf("fresh generation runtime status: %v", err)
	}
	if _, err := env.manager.Arm(context.Background(), "n1", "f1", "act-1", "198.51.100.7:8080"); err != nil {
		t.Fatalf("Arm after fresh same-activation generation status: %v", err)
	}
	if live, err := env.store.CountLiveProbeOperations(); err != nil || live != 1 {
		t.Fatalf("fresh-generation Arm live operation count = %d (err %v), want 1", live, err)
	}
}

func TestR16Q2ReceiptTerminalRaceDoesNotPersistEvidence(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.store.SetProbeOperationStatus(op.ID, "ARMED"); err != nil {
		t.Fatalf("arm operation: %v", err)
	}
	challenge := [protocol.ProbeDigestLen]byte{0x91}
	if err := env.store.SetProbeOperationChallenge(op.ID, hex.EncodeToString(challenge[:])); err != nil {
		t.Fatalf("persist challenge: %v", err)
	}
	receipt := signRCT1(t, env.nodePriv, arm, challenge)
	beforeRecord := make(chan struct{})
	releaseRecord := make(chan struct{})
	env.manager.beforeRecordProbeResult = func(operationID, kind, payloadHex string) {
		if operationID != op.ID || kind != "rct1" || payloadHex != hex.EncodeToString(receipt) {
			t.Errorf("receipt seam = %q/%q/%q", operationID, kind, payloadHex)
		}
		close(beforeRecord)
		<-releaseRecord
	}
	resultCh := make(chan error, 1)
	go func() {
		resultCh <- env.manager.HandleProbeMessage("n1", "probe_ingress_receipt", receipt)
	}()
	select {
	case <-beforeRecord:
	case <-time.After(2 * time.Second):
		t.Fatal("receipt did not reach pre-record barrier")
	}
	if err := env.store.SetProbeOperationStatusCAS(op.ID, "ARMED", string(protocol.OutcomeTimeout)); err != nil {
		t.Fatalf("terminalize operation during receipt race: %v", err)
	}
	close(releaseRecord)
	select {
	case err := <-resultCh:
		if err == nil {
			t.Fatal("racing receipt unexpectedly succeeded")
		}
		var marker interface{ PermanentProbeReceipt() bool }
		if !errors.As(err, &marker) || !marker.PermanentProbeReceipt() {
			t.Fatalf("racing receipt error = %v, want permanent receipt marker", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("receipt race handler did not return")
	}
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != string(protocol.OutcomeTimeout) {
		t.Fatalf("racing receipt operation status = %q, want TIMEOUT", got.Status)
	}
	results, err := env.store.ListProbeResults(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if result.Kind == "rct1" {
			t.Fatalf("terminal receipt race persisted RCT1 evidence: %+v", result)
		}
	}
}

func TestR16Q2MalformedReceiptErrorIsPermanent(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	err := env.manager.HandleProbeMessage("n1", "probe_ingress_receipt", []byte("not-an-RCT1-frame"))
	if err == nil {
		t.Fatal("malformed receipt was accepted")
	}
	var marker interface{ PermanentProbeReceipt() bool }
	if !errors.As(err, &marker) || !marker.PermanentProbeReceipt() {
		t.Fatalf("malformed receipt error = %v, want permanent probe-receipt marker", err)
	}
}

func TestR16Q2UnknownReceiptErrorIsPermanent(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	_, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	arm.ProbeID[0] ^= 0xff
	err := env.manager.HandleProbeMessage("n1", "probe_ingress_receipt", signRCT1(t, env.nodePriv, arm, [32]byte{1}))
	if err == nil {
		t.Fatal("unknown receipt was accepted")
	}
	var marker interface{ PermanentProbeReceipt() bool }
	if !errors.As(err, &marker) || !marker.PermanentProbeReceipt() {
		t.Fatalf("unknown receipt error = %v, want permanent probe-receipt marker", err)
	}
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown receipt error = %v, want store.ErrNotFound cause", err)
	}
}

func newR16QManager(t *testing.T, env *testEnv, maxActive int, clock func() time.Time) *Manager {
	t.Helper()
	mgr, err := NewManager(ManagerConfig{
		Store:               env.store,
		Keyring:             env.keyring,
		Clock:               clock,
		MaxActiveOperations: maxActive,
		SweepInterval:       time.Hour,
		NodePublicKey: func(string) (ed25519.PublicKey, bool) {
			return env.nodePub, true
		},
	})
	if err != nil {
		t.Fatalf("quality manager: %v", err)
	}
	return mgr
}

func openR16QRawDB(t *testing.T, env *testEnv) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+env.store.Path()+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(FULL)")
	if err != nil {
		t.Fatalf("open quality raw database: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func r16QArmWithIndex(base protocol.ProbeArm, index uint64) protocol.ProbeArm {
	arm := base
	binary.BigEndian.PutUint64(arm.ProbeID[:8], 0x52445141524d0000)
	binary.BigEndian.PutUint64(arm.ProbeID[8:], index)
	binary.BigEndian.PutUint64(arm.ExpiryOpaque[:8], 0x5244514f50415100)
	binary.BigEndian.PutUint64(arm.ExpiryOpaque[8:], index)
	return arm
}

// TestR16Q2PublishProbeJoinStorageFailureRemainsRetryable injects one
// transaction-local publication failure. The exact RCT1 is already durable
// when the final join fails, so replay must retry the join rather than create
// a new receipt or terminal rejection.
func TestR16Q2PublishProbeJoinStorageFailureRemainsRetryable(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.store.SetProbeOperationStatus(op.ID, "ARMED"); err != nil {
		t.Fatalf("arm operation: %v", err)
	}
	if err := env.store.SetProbeOperationStatus(op.ID, "IN_FLIGHT"); err != nil {
		t.Fatalf("start provider operation: %v", err)
	}

	challenge := [protocol.ProbeDigestLen]byte{0x72}
	challengeHash := sha256.Sum256(challenge[:])
	frame := protocol.ProviderFrame{
		ArmDigest:    arm.Digest(),
		ProbeID:      arm.ProbeID,
		ProviderID:   arm.ProviderID,
		Activation:   arm.Activation,
		Endpoint:     arm.Endpoint,
		ExpiryOpaque: arm.ExpiryOpaque,
		Challenge:    challenge,
	}
	frame.Signature = ed25519.Sign(env.provider.priv, frame.SigningBytes())
	wan1 := append(frame.Canonical(), frame.Signature...)
	ack := protocol.ProbeACK{ArmDigest: arm.Digest(), ChallengeHash: challengeHash}
	ack.Signature = ed25519.Sign(env.nodePriv, ack.SigningBytes())
	ack1 := append(ack.SigningBytes(), ack.Signature...)
	receipt := signRCT1(t, env.nodePriv, arm, challengeHash)
	providerEvidence := providerResult{
		Schema: providerResultSchema, ProbeID: op.ID, Accepted: true,
		ChallengeHash: hex.EncodeToString(challengeHash[:]),
		WAN1Frame:     hex.EncodeToString(wan1), ACK1Frame: hex.EncodeToString(ack1),
		Reason: "ack_verified", TimestampUnix: op.CreatedAt,
	}
	providerEvidence.Signature = hex.EncodeToString(ed25519.Sign(env.provider.priv, providerEvidence.canonical()))
	if err := env.store.RecordProbeResult(op.ID, "provider", mustJSON(providerEvidence)); err != nil {
		t.Fatalf("record provider evidence: %v", err)
	}
	if err := env.store.RecordProbeResult(op.ID, "wan1", hex.EncodeToString(wan1)); err != nil {
		t.Fatalf("record WAN1 evidence: %v", err)
	}
	if err := env.store.RecordProbeResult(op.ID, "ack1", hex.EncodeToString(ack1)); err != nil {
		t.Fatalf("record ACK1 evidence: %v", err)
	}
	if err := env.store.SetProbeOperationChallenge(op.ID, hex.EncodeToString(challengeHash[:])); err != nil {
		t.Fatalf("persist challenge: %v", err)
	}

	rawDB := openR16QRawDB(t, env)
	trigger := fmt.Sprintf(`CREATE TRIGGER test_publish_probe_join_failure
		BEFORE UPDATE OF status ON probe_operations
		WHEN OLD.id = %q AND OLD.status = 'IN_FLIGHT' AND NEW.status = 'OPEN_FROM_VANTAGE'
		BEGIN SELECT RAISE(ABORT, 'injected PublishProbeJoin storage failure'); END`, op.ID)
	if _, err := rawDB.Exec(trigger); err != nil {
		t.Fatalf("install publication fault: %v", err)
	}

	firstErr := env.manager.HandleProbeMessage("n1", "probe_ingress_receipt", receipt)
	if firstErr == nil {
		t.Fatal("faulted receipt unexpectedly succeeded")
	}
	if got, err := env.store.GetProbeOperation(op.ID); err != nil || got.Status != "IN_FLIGHT" {
		t.Fatalf("faulted join operation = %+v (err %v), want IN_FLIGHT", got, err)
	}
	results, err := env.store.ListProbeResults(op.ID)
	if err != nil {
		t.Fatalf("list faulted join evidence: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("faulted join evidence count = %d, want four artifacts: %+v", len(results), results)
	}
	wantReceipt := hex.EncodeToString(receipt)
	for _, result := range results {
		if result.Kind == "rct1" && result.PayloadHex != wantReceipt {
			t.Fatalf("faulted RCT1 payload = %q, want exact receipt %q", result.PayloadHex, wantReceipt)
		}
	}
	if _, err := rawDB.Exec(`DROP TRIGGER test_publish_probe_join_failure`); err != nil {
		t.Fatalf("remove publication fault: %v", err)
	}

	// Recovery must retry the durable provider round rather than requeueing a
	// fresh request. This is the race boundary that previously produced a second
	// provider result and a false terminal rejection.
	env.manager.recoverOperations()
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get recovered operation: %v", err)
	}
	if got.Status != string(protocol.OutcomeOpenFromVantage) {
		t.Fatalf("recovered operation status = %q, want OPEN_FROM_VANTAGE", got.Status)
	}

	if err := env.manager.HandleProbeMessage("n1", "probe_ingress_receipt", receipt); err != nil {
		t.Fatalf("exact receipt replay after storage failure: %v", err)
	}
	got, err = env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get replayed operation: %v", err)
	}
	if got.Status != string(protocol.OutcomeOpenFromVantage) {
		t.Fatalf("replayed operation status = %q, want OPEN_FROM_VANTAGE", got.Status)
	}
	results, err = env.store.ListProbeResults(op.ID)
	if err != nil {
		t.Fatalf("list replayed join evidence: %v", err)
	}
	countRCT1 := 0
	for _, result := range results {
		if result.Kind == "rct1" {
			countRCT1++
			if result.PayloadHex != wantReceipt {
				t.Fatalf("replayed RCT1 payload = %q, want exact receipt %q", result.PayloadHex, wantReceipt)
			}
		}
	}
	if countRCT1 != 1 {
		t.Fatalf("replayed RCT1 count = %d, want exactly one", countRCT1)
	}
}

// TestR16Q2RecoveryChallengePersistenceFailureRemainsRetryable injects a
// challenge-write failure while provider evidence is already durable. Recovery
// must keep the operation IN_FLIGHT, without manufacturing a terminal outcome,
// until a later recovery can persist the challenge and complete the join.
func TestR16Q2RecoveryChallengePersistenceFailureRemainsRetryable(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.store.SetProbeOperationStatus(op.ID, "ARMED"); err != nil {
		t.Fatalf("arm operation: %v", err)
	}
	if err := env.store.SetProbeOperationStatus(op.ID, "IN_FLIGHT"); err != nil {
		t.Fatalf("start provider operation: %v", err)
	}

	challenge := [protocol.ProbeDigestLen]byte{0x73}
	challengeHash := sha256.Sum256(challenge[:])
	frame := protocol.ProviderFrame{
		ArmDigest:    arm.Digest(),
		ProbeID:      arm.ProbeID,
		ProviderID:   arm.ProviderID,
		Activation:   arm.Activation,
		Endpoint:     arm.Endpoint,
		ExpiryOpaque: arm.ExpiryOpaque,
		Challenge:    challenge,
	}
	frame.Signature = ed25519.Sign(env.provider.priv, frame.SigningBytes())
	wan1 := append(frame.Canonical(), frame.Signature...)
	ack := protocol.ProbeACK{ArmDigest: arm.Digest(), ChallengeHash: challengeHash}
	ack.Signature = ed25519.Sign(env.nodePriv, ack.SigningBytes())
	ack1 := append(ack.SigningBytes(), ack.Signature...)
	receipt := signRCT1(t, env.nodePriv, arm, challengeHash)
	providerEvidence := providerResult{
		Schema: providerResultSchema, ProbeID: op.ID, Accepted: true,
		ChallengeHash: hex.EncodeToString(challengeHash[:]),
		WAN1Frame:     hex.EncodeToString(wan1), ACK1Frame: hex.EncodeToString(ack1),
		Reason: "ack_verified", TimestampUnix: op.CreatedAt,
	}
	providerEvidence.Signature = hex.EncodeToString(ed25519.Sign(env.provider.priv, providerEvidence.canonical()))
	if err := env.store.RecordProbeResult(op.ID, "provider", mustJSON(providerEvidence)); err != nil {
		t.Fatalf("record provider evidence: %v", err)
	}
	if err := env.store.RecordProbeResult(op.ID, "wan1", hex.EncodeToString(wan1)); err != nil {
		t.Fatalf("record WAN1 evidence: %v", err)
	}
	if err := env.store.RecordProbeResult(op.ID, "ack1", hex.EncodeToString(ack1)); err != nil {
		t.Fatalf("record ACK1 evidence: %v", err)
	}
	if err := env.store.RecordProbeResult(op.ID, "rct1", hex.EncodeToString(receipt)); err != nil {
		t.Fatalf("record RCT1 evidence: %v", err)
	}

	rawDB := openR16QRawDB(t, env)
	trigger := fmt.Sprintf(`CREATE TRIGGER test_probe_challenge_failure
		BEFORE UPDATE OF challenge_hash ON probe_operations
		WHEN OLD.id = %q AND OLD.challenge_hash = '' AND NEW.challenge_hash != ''
		BEGIN SELECT RAISE(ABORT, 'injected challenge persistence failure'); END`, op.ID)
	if _, err := rawDB.Exec(trigger); err != nil {
		t.Fatalf("install challenge persistence fault: %v", err)
	}

	env.manager.recoverOperations()
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get faulted recovery operation: %v", err)
	}
	if got.Status != "IN_FLIGHT" {
		t.Fatalf("faulted recovery operation status = %q, want IN_FLIGHT", got.Status)
	}
	if got.ChallengeHash != "" {
		t.Fatalf("faulted recovery challenge = %q, want empty", got.ChallengeHash)
	}
	if _, err := env.store.ControlOutboxItemByOperation(op.ID, "probe_outcome"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("faulted recovery queued probe outcome: %v", err)
	}

	if _, err := rawDB.Exec(`DROP TRIGGER test_probe_challenge_failure`); err != nil {
		t.Fatalf("remove challenge persistence fault: %v", err)
	}
	env.manager.recoverOperations()
	got, err = env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get recovered challenge operation: %v", err)
	}
	if got.Status != string(protocol.OutcomeOpenFromVantage) {
		t.Fatalf("recovered challenge operation status = %q, want OPEN_FROM_VANTAGE", got.Status)
	}
	if !strings.EqualFold(got.ChallengeHash, hex.EncodeToString(challengeHash[:])) {
		t.Fatalf("recovered challenge = %q, want %q", got.ChallengeHash, hex.EncodeToString(challengeHash[:]))
	}
}

func TestR16Q2RecoveryRejectsMalformedAcceptedProviderEvidence(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, _ := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.store.SetProbeOperationStatus(op.ID, "ARMED"); err != nil {
		t.Fatalf("arm operation: %v", err)
	}
	if err := env.store.SetProbeOperationStatus(op.ID, "IN_FLIGHT"); err != nil {
		t.Fatalf("start provider operation: %v", err)
	}

	// The provider row is durable but claims acceptance without the required
	// WAN1/ACK1 evidence. Recovery must fail closed rather than leave IN_FLIGHT
	// until expiry or issue a second provider challenge.
	malformed := providerResult{
		Schema: providerResultSchema, ProbeID: op.ID, Accepted: true,
		ChallengeHash: strings.Repeat("ab", protocol.ProbeDigestLen),
		TimestampUnix: op.CreatedAt,
	}
	// The provider result itself is correctly signed, but it omits the required
	// WAN1/ACK1 evidence. Recovery must reject the incomplete accepted result
	// before any artifact replay is attempted.
	malformed.Signature = hex.EncodeToString(ed25519.Sign(env.provider.priv, malformed.canonical()))
	if err := env.store.RecordProbeResult(op.ID, "provider", mustJSON(malformed)); err != nil {
		t.Fatalf("record malformed provider evidence: %v", err)
	}

	env.manager.recoverOperations()
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get recovered malformed operation: %v", err)
	}
	if got.Status != string(protocol.OutcomeRejected) {
		t.Fatalf("malformed accepted provider result status = %q, want REJECTED", got.Status)
	}
}

func makeR16QProviderEvidence(t *testing.T, env *testEnv, op store.ProbeOperation, arm protocol.ProbeArm, challengeByte byte) (providerResult, string, string) {
	t.Helper()
	challenge := [protocol.ProbeDigestLen]byte{challengeByte}
	frame := protocol.ProviderFrame{
		ArmDigest:    arm.Digest(),
		ProbeID:      arm.ProbeID,
		ProviderID:   arm.ProviderID,
		Activation:   arm.Activation,
		Endpoint:     arm.Endpoint,
		ExpiryOpaque: arm.ExpiryOpaque,
		Challenge:    challenge,
	}
	frame.Signature = ed25519.Sign(env.provider.priv, frame.SigningBytes())
	wan1 := append(frame.Canonical(), frame.Signature...)
	challengeHash := frame.ChallengeHash()
	ack := protocol.ProbeACK{ArmDigest: arm.Digest(), ChallengeHash: challengeHash}
	ack.Signature = ed25519.Sign(env.nodePriv, ack.SigningBytes())
	ack1 := append(ack.SigningBytes(), ack.Signature...)
	result := providerResult{
		Schema: providerResultSchema, ProbeID: op.ID, Accepted: true,
		ChallengeHash: hex.EncodeToString(challengeHash[:]),
		WAN1Frame:     hex.EncodeToString(wan1), ACK1Frame: hex.EncodeToString(ack1),
		Reason: "ack_verified", TimestampUnix: op.CreatedAt,
	}
	result.Signature = hex.EncodeToString(ed25519.Sign(env.provider.priv, result.canonical()))
	return result, hex.EncodeToString(wan1), hex.EncodeToString(ack1)
}

func TestR16Q2RecoveryRejectsMalformedAcceptedProviderChallenge(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.store.SetProbeOperationStatus(op.ID, "ARMED"); err != nil {
		t.Fatalf("arm operation: %v", err)
	}
	if err := env.store.SetProbeOperationStatus(op.ID, "IN_FLIGHT"); err != nil {
		t.Fatalf("start provider operation: %v", err)
	}
	result, wan1, ack1 := makeR16QProviderEvidence(t, env, op, arm, 0x74)
	result.ChallengeHash = "cafe"
	result.Signature = hex.EncodeToString(ed25519.Sign(env.provider.priv, result.canonical()))
	if err := env.store.RecordProbeResult(op.ID, "provider", mustJSON(result)); err != nil {
		t.Fatalf("record malformed challenge provider evidence: %v", err)
	}
	if err := env.store.RecordProbeResult(op.ID, "wan1", wan1); err != nil {
		t.Fatalf("record WAN1 evidence: %v", err)
	}
	if err := env.store.RecordProbeResult(op.ID, "ack1", ack1); err != nil {
		t.Fatalf("record ACK1 evidence: %v", err)
	}

	env.manager.recoverOperations()
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get recovered malformed challenge operation: %v", err)
	}
	if got.Status != string(protocol.OutcomeRejected) {
		t.Fatalf("malformed provider challenge status = %q, want REJECTED", got.Status)
	}
}

func TestR16Q2RecoveryRejectsConflictingProviderArtifact(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.store.SetProbeOperationStatus(op.ID, "ARMED"); err != nil {
		t.Fatalf("arm operation: %v", err)
	}
	if err := env.store.SetProbeOperationStatus(op.ID, "IN_FLIGHT"); err != nil {
		t.Fatalf("start provider operation: %v", err)
	}
	result, wan1, ack1 := makeR16QProviderEvidence(t, env, op, arm, 0x75)
	if err := env.store.RecordProbeResult(op.ID, "provider", mustJSON(result)); err != nil {
		t.Fatalf("record provider evidence: %v", err)
	}
	if err := env.store.RecordProbeResult(op.ID, "wan1", "00"); err != nil {
		t.Fatalf("record conflicting WAN1 evidence: %v", err)
	}
	if err := env.store.RecordProbeResult(op.ID, "ack1", ack1); err != nil {
		t.Fatalf("record ACK1 evidence: %v", err)
	}
	_ = wan1

	env.manager.recoverOperations()
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get recovered conflicting operation: %v", err)
	}
	if got.Status != string(protocol.OutcomeRejected) {
		t.Fatalf("conflicting provider artifact status = %q, want REJECTED", got.Status)
	}
}

func createR16QOperation(t *testing.T, env *testEnv, arm protocol.ProbeArm, status string, expiresAt int64) store.ProbeOperation {
	t.Helper()
	if err := arm.Validate(); err != nil {
		t.Fatalf("quality ARM %d: %v", binary.BigEndian.Uint64(arm.ProbeID[8:]), err)
	}
	op, err := env.store.CreateProbeOperation(store.ProbeOperation{
		ID:           hex.EncodeToString(arm.ProbeID[:]),
		NodeID:       "n1",
		ForwardID:    "f1",
		ActivationID: "act-1",
		ProviderID:   "prov-1",
		Status:       status,
		Endpoint:     arm.Endpoint,
		ArmHex:       hex.EncodeToString(arm.Canonical()),
		TTLMS:        arm.TTLMS,
		ExpiryOpaque: hex.EncodeToString(arm.ExpiryOpaque[:]),
		ExpiresAt:    expiresAt,
	})
	if err != nil {
		t.Fatalf("create quality operation: %v", err)
	}
	return op
}

// Expired live rows are retained until the sweeper runs, but they must not
// consume the MaxActiveOperations correlation page ahead of a current target.
func TestR16Q2ReceiptCorrelationSkipsExpiredBacklog(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	base := time.Now().Truncate(time.Second)
	mgr := newR16QManager(t, env, 1, func() time.Time { return base })
	current, currentArm := env.armAndGetPayload(t, "198.51.100.7:8080")
	for i := uint64(1); i <= 2; i++ {
		createR16QOperation(t, env, r16QArmWithIndex(currentArm, i), "PENDING", base.Unix()-1)
	}
	challenge := [32]byte{0x51}
	if err := env.store.SetProbeOperationStatus(current.ID, "ARMED"); err != nil {
		t.Fatalf("arm current operation: %v", err)
	}
	if err := env.store.SetProbeOperationChallenge(current.ID, hex.EncodeToString(challenge[:])); err != nil {
		t.Fatalf("set current challenge: %v", err)
	}
	if err := mgr.HandleProbeMessage("n1", "probe_ingress_receipt", signRCT1(t, env.nodePriv, currentArm, challenge)); err != nil {
		if errors.Is(err, store.ErrProbeLookupBudget) || errors.Is(err, store.ErrNotFound) {
			t.Fatalf("current receipt hidden by expired backlog: %v", err)
		}
		t.Fatalf("current receipt: %v", err)
	}
	got, err := env.store.GetProbeOperation(current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "ARMED" {
		t.Fatalf("current receipt changed operation status to %q, want ARMED", got.Status)
	}
}

// Recovery expires old rows separately from the live page. An expired
// historical row must not hide newer work when MaxActiveOperations is small.
func TestR16Q2RecoverySkipsExpiredBacklog(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	base := time.Now().Truncate(time.Second)
	_, baseArm := env.armAndGetPayload(t, "198.51.100.7:8080")
	oldArm := r16QArmWithIndex(baseArm, 0x61)
	old := createR16QOperation(t, env, oldArm, "ARMED", base.Unix()-1)
	liveArm := r16QArmWithIndex(baseArm, 0x62)
	live := createR16QOperation(t, env, liveArm, "ARMED", base.Unix()+60)
	if err := env.store.SetProbeProviderIndependentVantage("prov-1", false); err != nil {
		t.Fatal(err)
	}
	mgr := newR16QManager(t, env, 1, func() time.Time { return base })
	mgr.recoverOperations()
	oldGot, err := env.store.GetProbeOperation(old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if oldGot.Status != string(protocol.OutcomeTimeout) {
		t.Fatalf("expired recovery row status = %q, want TIMEOUT", oldGot.Status)
	}
	liveGot, err := env.store.GetProbeOperation(live.ID)
	if err != nil {
		t.Fatal(err)
	}
	if liveGot.Status != string(protocol.OutcomeNoIndependentVantage) {
		t.Fatalf("live recovery row status = %q, want NO_INDEPENDENT_VANTAGE", liveGot.Status)
	}
}

// Recovery's MaxActiveOperations value is a per-pass work budget, not a
// permanent prefix. A still-live offline row must not starve later work for an
// online node across repeated recovery passes.
func TestR16Q2RecoveryMakesFairProgressPastOfflineLiveRow(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	if err := env.store.CreateNode(store.Node{ID: "n2", Name: "n2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.CreateForward(store.Forward{
		ID: "f2", NodeID: "n2", Name: "fwd-2", Protocol: "tcp",
		CurrentActivationID: "act-2", Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Truncate(time.Second)
	_, baseArm := env.armAndGetPayload(t, "198.51.100.7:8080")
	firstArm := r16QArmWithIndex(baseArm, 0x71)
	first, err := env.store.CreateProbeOperation(store.ProbeOperation{
		ID: "r16q2-fair-offline", NodeID: "n1", ForwardID: "f1", ActivationID: "act-1",
		ExpectedForwardRevision: 1, ProviderID: "prov-1", Status: "ARMED",
		Endpoint: firstArm.Endpoint, ArmHex: hex.EncodeToString(firstArm.Canonical()),
		TTLMS: firstArm.TTLMS, ExpiryOpaque: hex.EncodeToString(firstArm.ExpiryOpaque[:]),
		ExpiresAt: base.Unix() + 60,
	})
	if err != nil {
		t.Fatalf("create offline recovery row: %v", err)
	}
	secondArm := r16QArmWithIndex(baseArm, 0x72)
	second, err := env.store.CreateProbeOperation(store.ProbeOperation{
		ID: "r16q2-fair-online", NodeID: "n2", ForwardID: "f2", ActivationID: "act-2",
		ExpectedForwardRevision: 1, ProviderID: "prov-1", Status: "ARMED",
		Endpoint: secondArm.Endpoint, ArmHex: hex.EncodeToString(secondArm.Canonical()),
		TTLMS: secondArm.TTLMS, ExpiryOpaque: hex.EncodeToString(secondArm.ExpiryOpaque[:]),
		ExpiresAt: base.Unix() + 120,
	})
	if err != nil {
		t.Fatalf("create online recovery row: %v", err)
	}
	if err := env.store.SetProbeProviderIndependentVantage("prov-1", false); err != nil {
		t.Fatalf("disable provider for fair recovery assertion: %v", err)
	}
	mgr, err := NewManager(ManagerConfig{
		Store: env.store, Keyring: env.keyring, Clock: func() time.Time { return base },
		MaxActiveOperations: 1, SweepInterval: time.Hour,
		NodePublicKey: func(nodeID string) (ed25519.PublicKey, bool) {
			if nodeID == "n2" {
				return env.nodePub, true
			}
			return nil, false
		},
	})
	if err != nil {
		t.Fatalf("fair recovery manager: %v", err)
	}
	defer mgr.Close()
	if err := mgr.recoverOperations(); err != nil {
		t.Fatalf("first fair recovery pass: %v", err)
	}
	firstGot, err := env.store.GetProbeOperation(first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if firstGot.Status != "ARMED" {
		t.Fatalf("offline prefix status after first pass = %q, want ARMED", firstGot.Status)
	}
	if err := mgr.recoverOperations(); err != nil {
		t.Fatalf("second fair recovery pass: %v", err)
	}
	secondGot, err := env.store.GetProbeOperation(second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if secondGot.Status != string(protocol.OutcomeNoIndependentVantage) {
		t.Fatalf("online recovery row remained unrecovered after fair pass: %q", secondGot.Status)
	}
	firstGot, err = env.store.GetProbeOperation(first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if firstGot.Status != "ARMED" {
		t.Fatalf("offline prefix changed while recovering later row: %q", firstGot.Status)
	}
}

// A malformed persisted challenge is an internal recovery condition. The
// authenticated receipt must remain retryable rather than being marked as a
// permanent bad frame.
func TestR16Q2StoredChallengeCorruptionIsRetryable(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.store.SetProbeOperationStatus(op.ID, "ARMED"); err != nil {
		t.Fatalf("arm operation: %v", err)
	}
	db := openR16QRawDB(t, env)
	if _, err := db.Exec(`UPDATE probe_operations SET challenge_hash = ? WHERE id = ?`, "not-a-sha256-hash", op.ID); err != nil {
		t.Fatalf("corrupt stored challenge: %v", err)
	}
	err := env.manager.HandleProbeMessage("n1", "probe_ingress_receipt", signRCT1(t, env.nodePriv, arm, [32]byte{0x52}))
	if err == nil {
		t.Fatal("receipt with corrupt stored challenge was accepted")
	}
	var marker interface{ PermanentProbeReceipt() bool }
	if errors.As(err, &marker) && marker.PermanentProbeReceipt() {
		t.Fatalf("corrupt challenge error was marked permanent: %v", err)
	}
	if got, getErr := env.store.GetProbeOperation(op.ID); getErr != nil || got.Status != "ARMED" {
		t.Fatalf("corrupt challenge changed operation: %+v (err %v)", got, getErr)
	}
}

// Persisted ARM corruption is controller recovery state, not proof that the
// authenticated receipt is invalid. The receipt remains retryable and the
// operation remains unchanged for operator repair or normal expiry.
func TestR16Q2StoredArmCorruptionIsRetryable(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.store.SetProbeOperationStatus(op.ID, "ARMED"); err != nil {
		t.Fatalf("arm operation: %v", err)
	}
	db := openR16QRawDB(t, env)
	if _, err := db.Exec(`UPDATE probe_operations SET arm_hex = ? WHERE id = ?`, "not-an-arm", op.ID); err != nil {
		t.Fatalf("corrupt stored ARM: %v", err)
	}
	err := env.manager.HandleProbeMessage("n1", "probe_ingress_receipt", signRCT1(t, env.nodePriv, arm, [32]byte{0x53}))
	if err == nil {
		t.Fatal("receipt with corrupt stored ARM was accepted")
	}
	if !errors.Is(err, store.ErrProbeCorrupt) {
		t.Fatalf("stored ARM corruption error = %v, want ErrProbeCorrupt cause", err)
	}
	var marker interface{ PermanentProbeReceipt() bool }
	if errors.As(err, &marker) && marker.PermanentProbeReceipt() {
		t.Fatalf("corrupt ARM error = %v, want retryable corruption", err)
	}
	if got, getErr := env.store.GetProbeOperation(op.ID); getErr != nil || got.Status != "ARMED" {
		t.Fatalf("corrupt ARM changed operation: %+v (err %v)", got, getErr)
	}
}

// The manager's lookup budget follows MaxActiveOperations rather than the
// store's historical 1024-row default. A valid RDY1 at row 1025 must correlate.
func TestR16Q2HandleArmedSupportsConfiguredBudgetBeyond1024(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	baseOp, baseArm := env.armAndGetPayload(t, "198.51.100.7:8080")
	fillerExpiry := baseOp.ExpiresAt
	for i := uint64(1); i < 1024; i++ {
		createR16QOperation(t, env, r16QArmWithIndex(baseArm, i), "PENDING", fillerExpiry)
	}
	targetArm := r16QArmWithIndex(baseArm, 1024)
	target := createR16QOperation(t, env, targetArm, "PENDING", fillerExpiry+1)
	if err := env.store.SetProbeProviderIndependentVantage("prov-1", false); err != nil {
		t.Fatalf("disable provider for synchronous correlation assertion: %v", err)
	}
	base := time.Now()
	mgr := newR16QManager(t, env, 1025, func() time.Time { return base })
	if err := mgr.HandleProbeMessage("n1", "probe_armed", signRDY1(t, env.nodePriv, targetArm)); err != nil {
		if errors.Is(err, store.ErrProbeLookupBudget) || errors.Is(err, store.ErrNotFound) {
			t.Fatalf("target beyond historical 1024-row budget was not correlated: %v", err)
		}
		t.Fatalf("target RDY1: %v", err)
	}
	got, err := env.store.GetProbeOperation(target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != string(protocol.OutcomeNoIndependentVantage) {
		t.Fatalf("target status = %q, want synchronous NO_INDEPENDENT_VANTAGE after correlation", got.Status)
	}
}

// Provider result validation must not depend on the node session being online.
// A malformed accepted provider result is durable evidence corruption and can
// be rejected during restart even when ACK1 cannot yet be authenticated.
func TestR16Q2RecoveryRejectsMalformedWAN1WhileNodeOffline(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.store.SetProbeOperationStatus(op.ID, "ARMED"); err != nil {
		t.Fatalf("arm operation: %v", err)
	}
	if err := env.store.SetProbeOperationStatus(op.ID, "IN_FLIGHT"); err != nil {
		t.Fatalf("start provider operation: %v", err)
	}
	result, _, ack1 := makeR16QProviderEvidence(t, env, op, arm, 0x77)
	result.WAN1Frame = "00"
	result.Signature = hex.EncodeToString(ed25519.Sign(env.provider.priv, result.canonical()))
	if err := env.store.RecordProbeResult(op.ID, "provider", mustJSON(result)); err != nil {
		t.Fatalf("record malformed WAN1 provider result: %v", err)
	}
	if err := env.store.RecordProbeResult(op.ID, "ack1", ack1); err != nil {
		t.Fatalf("record ACK1 artifact: %v", err)
	}
	online := false
	mgr, err := NewManager(ManagerConfig{
		Store: env.store, Keyring: env.keyring, Clock: time.Now,
		MaxActiveOperations: 16, SweepInterval: time.Hour,
		NodePublicKey: func(string) (ed25519.PublicKey, bool) {
			if !online {
				return nil, false
			}
			return env.nodePub, true
		},
	})
	if err != nil {
		t.Fatalf("offline recovery manager: %v", err)
	}
	mgr.recoverOperations()
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get malformed WAN1 operation: %v", err)
	}
	if got.Status != string(protocol.OutcomeRejected) {
		t.Fatalf("malformed WAN1 status = %q, want REJECTED", got.Status)
	}
}

func TestR16Q2RecoveryDefersMalformedACK1UntilReconnect(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.store.SetProbeOperationStatus(op.ID, "ARMED"); err != nil {
		t.Fatalf("arm operation: %v", err)
	}
	if err := env.store.SetProbeOperationStatus(op.ID, "IN_FLIGHT"); err != nil {
		t.Fatalf("start provider operation: %v", err)
	}
	result, wan1, _ := makeR16QProviderEvidence(t, env, op, arm, 0x78)
	result.ACK1Frame = "zz"
	result.Signature = hex.EncodeToString(ed25519.Sign(env.provider.priv, result.canonical()))
	if err := env.store.RecordProbeResult(op.ID, "provider", mustJSON(result)); err != nil {
		t.Fatalf("record malformed ACK1 provider result: %v", err)
	}
	if err := env.store.RecordProbeResult(op.ID, "wan1", wan1); err != nil {
		t.Fatalf("record WAN1 artifact: %v", err)
	}
	online := false
	mgr, err := NewManager(ManagerConfig{
		Store: env.store, Keyring: env.keyring, Clock: time.Now,
		MaxActiveOperations: 16, SweepInterval: time.Hour,
		NodePublicKey: func(string) (ed25519.PublicKey, bool) {
			if !online {
				return nil, false
			}
			return env.nodePub, true
		},
	})
	if err != nil {
		t.Fatalf("offline recovery manager: %v", err)
	}
	mgr.recoverOperations()
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get offline malformed ACK1 operation: %v", err)
	}
	if got.Status != "IN_FLIGHT" {
		t.Fatalf("offline malformed ACK1 status = %q, want IN_FLIGHT", got.Status)
	}
	online = true
	mgr.recoverOperations()
	got, err = env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get reconnected malformed ACK1 operation: %v", err)
	}
	if got.Status != string(protocol.OutcomeRejected) {
		t.Fatalf("reconnected malformed ACK1 status = %q, want REJECTED", got.Status)
	}
}

func TestR16Q2RecoveryRejectsMalformedProviderEvidenceWhileNodeOffline(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, _ := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.store.SetProbeOperationStatus(op.ID, "ARMED"); err != nil {
		t.Fatalf("arm operation: %v", err)
	}
	if err := env.store.SetProbeOperationStatus(op.ID, "IN_FLIGHT"); err != nil {
		t.Fatalf("start provider operation: %v", err)
	}
	malformed := providerResult{
		Schema: providerResultSchema, ProbeID: op.ID, Accepted: true,
		ChallengeHash: strings.Repeat("ab", protocol.ProbeDigestLen),
		TimestampUnix: op.CreatedAt,
	}
	malformed.Signature = hex.EncodeToString(ed25519.Sign(env.provider.priv, malformed.canonical()))
	if err := env.store.RecordProbeResult(op.ID, "provider", mustJSON(malformed)); err != nil {
		t.Fatalf("record malformed provider result: %v", err)
	}
	online := false
	mgr, err := NewManager(ManagerConfig{
		Store: env.store, Keyring: env.keyring, Clock: time.Now,
		MaxActiveOperations: 16, SweepInterval: time.Hour,
		NodePublicKey: func(string) (ed25519.PublicKey, bool) {
			if !online {
				return nil, false
			}
			return env.nodePub, true
		},
	})
	if err != nil {
		t.Fatalf("offline recovery manager: %v", err)
	}
	mgr.recoverOperations()
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get malformed offline operation: %v", err)
	}
	if got.Status != string(protocol.OutcomeRejected) {
		t.Fatalf("malformed offline provider result status = %q, want REJECTED", got.Status)
	}
}

// Valid provider/WAN1 evidence remains durable while the node session is
// offline. Once the node reconnects, ACK1 is validated and the existing round
// completes without issuing a fresh provider challenge.
func TestR16Q2RecoveryDefersValidProviderEvidenceUntilNodeReconnects(t *testing.T) {
	env := newTestEnv(t, false)
	env.createNodeForward(t)
	op, arm := env.armAndGetPayload(t, "198.51.100.7:8080")
	if err := env.store.SetProbeOperationStatus(op.ID, "ARMED"); err != nil {
		t.Fatalf("arm operation: %v", err)
	}
	if err := env.store.SetProbeOperationStatus(op.ID, "IN_FLIGHT"); err != nil {
		t.Fatalf("start provider operation: %v", err)
	}
	result, wan1, ack1 := makeR16QProviderEvidence(t, env, op, arm, 0x76)
	if err := env.store.RecordProbeResult(op.ID, "provider", mustJSON(result)); err != nil {
		t.Fatalf("record provider result: %v", err)
	}
	challengeHash, err := hex.DecodeString(result.ChallengeHash)
	if err != nil || len(challengeHash) != protocol.ProbeDigestLen {
		t.Fatalf("provider challenge hash fixture: %v", err)
	}
	var challengeDigest [protocol.ProbeDigestLen]byte
	copy(challengeDigest[:], challengeHash)
	receipt := signRCT1(t, env.nodePriv, arm, challengeDigest)
	if err := env.store.RecordProbeResult(op.ID, "rct1", hex.EncodeToString(receipt)); err != nil {
		t.Fatalf("record RCT1 result: %v", err)
	}
	online := false
	mgr, err := NewManager(ManagerConfig{
		Store: env.store, Keyring: env.keyring, Clock: time.Now,
		MaxActiveOperations: 16, SweepInterval: time.Hour,
		NodePublicKey: func(string) (ed25519.PublicKey, bool) {
			if !online {
				return nil, false
			}
			return env.nodePub, true
		},
	})
	if err != nil {
		t.Fatalf("offline recovery manager: %v", err)
	}
	mgr.recoverOperations()
	got, err := env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get offline operation: %v", err)
	}
	if got.Status != "IN_FLIGHT" {
		t.Fatalf("offline valid provider result status = %q, want IN_FLIGHT", got.Status)
	}
	if got.ChallengeHash == "" {
		t.Fatal("offline recovery did not persist provider challenge")
	}
	if results, err := env.store.ListProbeResults(op.ID); err != nil {
		t.Fatalf("list offline evidence: %v", err)
	} else {
		wantOffline := map[string]string{"provider": mustJSON(result), "wan1": wan1, "ack1": ack1}
		for kind, expected := range wantOffline {
			found := false
			for _, item := range results {
				if item.Kind == kind {
					found = true
					if !strings.EqualFold(item.PayloadHex, expected) {
						t.Fatalf("offline %s artifact = %q, want %q", kind, item.PayloadHex, expected)
					}
				}
			}
			if !found {
				t.Fatalf("offline recovery did not persist %s artifact", kind)
			}
		}
	}

	online = true
	mgr.recoverOperations()
	got, err = env.store.GetProbeOperation(op.ID)
	if err != nil {
		t.Fatalf("get reconnected operation: %v", err)
	}
	if got.Status != string(protocol.OutcomeOpenFromVantage) {
		t.Fatalf("reconnected operation status = %q, want OPEN_FROM_VANTAGE", got.Status)
	}
	results, err := env.store.ListProbeResults(op.ID)
	if err != nil {
		t.Fatalf("list reconnected evidence: %v", err)
	}
	want := map[string]string{"provider": mustJSON(result), "wan1": wan1, "ack1": ack1, "rct1": hex.EncodeToString(receipt)}
	for _, item := range results {
		if expected, ok := want[item.Kind]; ok && !strings.EqualFold(item.PayloadHex, expected) {
			t.Fatalf("%s artifact = %q, want %q", item.Kind, item.PayloadHex, expected)
		}
	}
}
