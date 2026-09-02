package hook

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// Secret-binding, signature-budget and signing-allowlist store accessors.
//
// These are INTERNAL to internal/hook (P1-2): the broker enforces a secret is
// bound to the hook it signs for, a durable per-secret signature budget caps
// the total number of signatures a secret can ever issue (never an unlimited
// HMAC oracle), and query-placement signing only signs params explicitly
// allowlisted per hook. None of this is part of the frozen OpenAPI surface;
// the binding/allowlist wiring is composed by P17.

// BindSecretToHook durably binds one secret to one hook. Signing for a
// delivery whose (hook_id, secret_id) pair is not bound fails closed
// (ErrSecretNotBoundToHook in the broker). Binding is idempotent.
func (s *Store) BindSecretToHook(hookID, secretID string) error {
	if hookID == "" || secretID == "" {
		return fmt.Errorf("%w: hook_id and secret_id are required", ErrInvalid)
	}
	if _, err := s.GetDefinition(hookID); err != nil {
		return err
	}
	if _, err := s.GetSecret(secretID); err != nil {
		return err
	}
	ts := s.currentUnix()
	if _, err := s.db.Exec(
		`INSERT INTO hook_secret_bindings (hook_id, secret_id, created_at) VALUES (?, ?, ?)
		   ON CONFLICT(hook_id, secret_id) DO NOTHING`, hookID, secretID, ts); err != nil {
		return fmt.Errorf("hook: bind secret: %w", err)
	}
	return nil
}

// IsSecretBoundToHook reports whether the secret is bound to the hook.
func (s *Store) IsSecretBoundToHook(hookID, secretID string) (bool, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM hook_secret_bindings WHERE hook_id = ? AND secret_id = ?`,
		hookID, secretID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("hook: check secret binding: %w", err)
	}
	return n == 1, nil
}

// UnbindSecretFromHook removes the binding (operational/internal use).
func (s *Store) UnbindSecretFromHook(hookID, secretID string) error {
	if _, err := s.db.Exec(
		`DELETE FROM hook_secret_bindings WHERE hook_id = ? AND secret_id = ?`,
		hookID, secretID); err != nil {
		return fmt.Errorf("hook: unbind secret: %w", err)
	}
	return nil
}

// SetSecretSignatureBudget sets the durable total-signature cap for a secret.
// budget 0 disables signing entirely (fail closed). signature_issued is the
// running counter; it is never reset by this call.
func (s *Store) SetSecretSignatureBudget(secretID string, budget int64) error {
	if secretID == "" {
		return fmt.Errorf("%w: secret_id is required", ErrInvalid)
	}
	if budget < 0 {
		return fmt.Errorf("%w: signature budget must not be negative", ErrInvalid)
	}
	res, err := s.db.Exec(
		`UPDATE hook_secrets SET signature_budget = ?, updated_at = ? WHERE secret_id = ?`,
		budget, s.currentUnix(), secretID)
	if err != nil {
		return fmt.Errorf("hook: set signature budget: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// ReserveSecretSignature durably consumes one unit of the secret's signature
// budget. It fails closed (ErrNoSignatureBudget / ErrSignatureBudgetExhausted)
// and is atomic under SQLite's writer serialization: two concurrent Sign calls
// against a nearly-exhausted budget cannot both reserve.
//
// signature_issued and signature_budget are MONOTONIC durable counters: a
// secret never re-issues past its budget, and ReserveSecretSignature never
// decrements them. When a secret's budget is exhausted the operator must RAISE
// it explicitly (SetSecretSignatureBudget) — the counter is never reset by
// creating a new delivery or retrying one.
func (s *Store) ReserveSecretSignature(secretID string) error {
	var issued, budget int64
	err := s.db.QueryRow(
		`SELECT signature_issued, signature_budget FROM hook_secrets WHERE secret_id = ?`,
		secretID).Scan(&issued, &budget)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("hook: read signature budget: %w", err)
	}
	if budget <= 0 {
		return ErrNoSignatureBudget
	}
	res, err := s.db.Exec(
		`UPDATE hook_secrets
		    SET signature_issued = signature_issued + 1, updated_at = ?
		  WHERE secret_id = ? AND signature_issued < signature_budget`,
		s.currentUnix(), secretID)
	if err != nil {
		return fmt.Errorf("hook: reserve signature: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrSignatureBudgetExhausted
	}
	return nil
}

// SignatureUsage returns the secret's durable budget and issued count (tests /
// operational observability; never exposed by the API).
func (s *Store) SignatureUsage(secretID string) (issued, budget int64, err error) {
	err = s.db.QueryRow(
		`SELECT signature_issued, signature_budget FROM hook_secrets WHERE secret_id = ?`,
		secretID).Scan(&issued, &budget)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, ErrNotFound
	}
	if err != nil {
		return 0, 0, fmt.Errorf("hook: read signature usage: %w", err)
	}
	return issued, budget, nil
}

// SetHookParamsAllowlist replaces the per-hook signing param allowlist
// (internal API; absent allowlist -> query-placement signing fails closed with
// ErrNoParamsAllowlist).
func (s *Store) SetHookParamsAllowlist(hookID string, allowed []string) error {
	if hookID == "" {
		return fmt.Errorf("%w: hook_id is required", ErrInvalid)
	}
	raw, err := json.Marshal(allowed)
	if err != nil {
		return fmt.Errorf("hook: marshal params allowlist: %w", err)
	}
	res, err := s.db.Exec(
		`UPDATE hook_definitions SET allow_params_json = ?, updated_at = ? WHERE id = ?`,
		string(raw), s.currentUnix(), hookID)
	if err != nil {
		return fmt.Errorf("hook: set params allowlist: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// GetHookParamsAllowlist returns the per-hook signing param allowlist. An
// empty (absent) allowlist grants nothing: query-placement signing fails
// closed rather than falling back to an allow-all oracle.
func (s *Store) GetHookParamsAllowlist(hookID string) ([]string, error) {
	var raw string
	err := s.db.QueryRow(
		`SELECT allow_params_json FROM hook_definitions WHERE id = ?`, hookID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("hook: read params allowlist: %w", err)
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("hook: parse params allowlist: %w", err)
	}
	return out, nil
}
