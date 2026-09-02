package hook

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// CreateDefinition inserts a webhook definition at revision 1 and returns it.
func (s *Store) CreateDefinition(name, kind, url string) (Definition, error) {
	id, err := randomHookID()
	if err != nil {
		return Definition{}, err
	}
	ts := s.currentUnix()
	_, err = s.db.Exec(`INSERT INTO hook_definitions
		(id, name, kind, url, allow_params_json, revision, created_at, updated_at)
		VALUES (?, ?, ?, ?, '[]', 1, ?, ?)`, id, name, kind, url, ts, ts)
	if err != nil {
		return Definition{}, fmt.Errorf("hook: create definition: %w", err)
	}
	return s.GetDefinition(id)
}

// ListDefinitions returns every webhook definition ordered by name.
func (s *Store) ListDefinitions() ([]Definition, error) {
	rows, err := s.db.Query(
		`SELECT id, name, kind, url, allow_params_json, revision, created_at, updated_at
		   FROM hook_definitions ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("hook: list definitions: %w", err)
	}
	var out []Definition
	if err := scanAll(rows, nil, func(r *sql.Rows) error {
		var d Definition
		var allowRaw string
		if err := r.Scan(&d.ID, &d.Name, &d.Kind, &d.URL, &allowRaw, &d.Revision, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(allowRaw), &d.AllowParams); err != nil {
			return fmt.Errorf("hook: parse allow_params_json: %w", err)
		}
		out = append(out, d)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// GetDefinition returns one definition.
func (s *Store) GetDefinition(id string) (Definition, error) {
	var d Definition
	var allowRaw string
	err := s.db.QueryRow(
		`SELECT id, name, kind, url, allow_params_json, revision, created_at, updated_at
		   FROM hook_definitions WHERE id = ?`, id,
	).Scan(&d.ID, &d.Name, &d.Kind, &d.URL, &allowRaw, &d.Revision, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Definition{}, ErrNotFound
	}
	if err != nil {
		return Definition{}, fmt.Errorf("hook: get definition: %w", err)
	}
	if err := json.Unmarshal([]byte(allowRaw), &d.AllowParams); err != nil {
		return Definition{}, fmt.Errorf("hook: parse allow_params_json: %w", err)
	}
	return d, nil
}

// UpdateDefinition applies a revision-CAS patch.
func (s *Store) UpdateDefinition(id string, name, url *string, expectedRev uint64) (Definition, error) {
	ts := s.currentUnix()
	// Read the current values so a patch that omits a field leaves it intact.
	current, err := s.GetDefinition(id)
	if err != nil {
		return Definition{}, err
	}
	setName, setURL := current.Name, current.URL
	if name != nil {
		setName = *name
	}
	if url != nil {
		setURL = *url
	}
	res, err := s.db.Exec(
		`UPDATE hook_definitions
		    SET name = ?, url = ?, revision = revision + 1, updated_at = ?
		  WHERE id = ? AND revision = ?`,
		setName, setURL, ts, id, expectedRev)
	if err != nil {
		return Definition{}, fmt.Errorf("hook: update definition: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		if _, getErr := s.GetDefinition(id); errors.Is(getErr, ErrNotFound) {
			return Definition{}, ErrNotFound
		}
		return Definition{}, ErrCASConflict
	}
	return s.GetDefinition(id)
}

// DeleteDefinition removes a definition under the expected revision. Any
// deliveries referencing the definition cascade (ON DELETE CASCADE).
func (s *Store) DeleteDefinition(id string, expectedRev uint64) error {
	res, err := s.db.Exec(
		`DELETE FROM hook_definitions WHERE id = ? AND revision = ?`, id, expectedRev)
	if err != nil {
		return fmt.Errorf("hook: delete definition: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		if _, getErr := s.GetDefinition(id); errors.Is(getErr, ErrNotFound) {
			return ErrNotFound
		}
		return ErrCASConflict
	}
	return nil
}

// defaultSecretSignatureBudget is the durable total-signature hard cap applied
// when a secret is created through the PUBLIC create path (Store.CreateSecret is
// the single insertion point behind POST /api/v1/hooks/secrets). The budget only
// bounds the TOTAL number of signatures a secret can ever issue (defense against
// an unlimited HMAC oracle); WHAT can be signed is already bound by the endpoint
// derivation, hook-binding and per-hook params allowlist (P1-2). Operators can
// raise or lower it via the internal SetSecretSignatureBudget API, or set it to
// 0 to disable signing entirely (fail closed). The migration default remains 0
// so any hypothetical insert that does not explicitly budget a secret fails
// closed at the broker.
const defaultSecretSignatureBudget int64 = 1024

// CreateSecret inserts encrypted secret material. secret_id is unique.
func (s *Store) CreateSecret(secretID, algorithm string, ciphertext []byte, keyID string) (Secret, error) {
	id, err := randomHookID()
	if err != nil {
		return Secret{}, err
	}
	ts := s.currentUnix()
	_, err = s.db.Exec(`INSERT INTO hook_secrets
		(id, secret_id, algorithm, ciphertext, key_id, signature_budget, revision, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`,
		id, secretID, algorithm, ciphertext, keyID, defaultSecretSignatureBudget, ts, ts)
	if err != nil {
		if isUniqueViolation(err) {
			return Secret{}, ErrConflict
		}
		return Secret{}, fmt.Errorf("hook: create secret: %w", err)
	}
	return s.GetSecret(secretID)
}

// GetSecret returns secret metadata by secret_id.
func (s *Store) GetSecret(secretID string) (Secret, error) {
	var sec Secret
	err := s.db.QueryRow(
		`SELECT id, secret_id, algorithm, revision, created_at, updated_at
		   FROM hook_secrets WHERE secret_id = ?`, secretID,
	).Scan(&sec.ID, &sec.SecretID, &sec.Algorithm, &sec.Revision, &sec.CreatedAt, &sec.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, ErrNotFound
	}
	if err != nil {
		return Secret{}, fmt.Errorf("hook: get secret: %w", err)
	}
	return sec, nil
}

// GetSecretRow returns secret metadata plus the at-rest material for the
// broker. The plaintext value is never returned; callers decrypt per-signing.
func (s *Store) GetSecretRow(secretID string) (SecretRow, error) {
	var row SecretRow
	err := s.db.QueryRow(
		`SELECT id, secret_id, algorithm, ciphertext, key_id, revision, created_at, updated_at
		   FROM hook_secrets WHERE secret_id = ?`, secretID,
	).Scan(&row.ID, &row.SecretID, &row.Algorithm, &row.Ciphertext, &row.KeyID,
		&row.Revision, &row.CreatedAt, &row.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SecretRow{}, ErrNotFound
	}
	if err != nil {
		return SecretRow{}, fmt.Errorf("hook: get secret row: %w", err)
	}
	return row, nil
}

// ListSecrets returns hook-secret metadata (never values), ordered by secret_id.
func (s *Store) ListSecrets() ([]Secret, error) {
	rows, err := s.db.Query(
		`SELECT id, secret_id, algorithm, revision, created_at, updated_at
		   FROM hook_secrets ORDER BY secret_id, id`)
	if err != nil {
		return nil, fmt.Errorf("hook: list secrets: %w", err)
	}
	var out []Secret
	if err := scanAll(rows, nil, func(r *sql.Rows) error {
		var sec Secret
		if err := r.Scan(&sec.ID, &sec.SecretID, &sec.Algorithm, &sec.Revision, &sec.CreatedAt, &sec.UpdatedAt); err != nil {
			return err
		}
		out = append(out, sec)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteSecret removes a secret under the expected revision.
func (s *Store) DeleteSecret(id string, expectedRev uint64) error {
	res, err := s.db.Exec(
		`DELETE FROM hook_secrets WHERE id = ? AND revision = ?`, id, expectedRev)
	if err != nil {
		return fmt.Errorf("hook: delete secret: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		if _, getErr := s.GetSecretByID(id); errors.Is(getErr, ErrNotFound) {
			return ErrNotFound
		}
		return ErrCASConflict
	}
	return nil
}

// GetSecretByID returns secret metadata by row id (the API identifies secrets
// by their row id in the /api/v1/hooks/secrets/{id} path).
func (s *Store) GetSecretByID(id string) (Secret, error) {
	var sec Secret
	err := s.db.QueryRow(
		`SELECT id, secret_id, algorithm, revision, created_at, updated_at
		   FROM hook_secrets WHERE id = ?`, id,
	).Scan(&sec.ID, &sec.SecretID, &sec.Algorithm, &sec.Revision, &sec.CreatedAt, &sec.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, ErrNotFound
	}
	if err != nil {
		return Secret{}, fmt.Errorf("hook: get secret by id: %w", err)
	}
	return sec, nil
}

func isUniqueViolation(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "UNIQUE constraint") || strings.Contains(err.Error(), "constraint failed"))
}
