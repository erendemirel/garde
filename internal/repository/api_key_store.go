package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"garde/internal/models"
)

const apiKeyColumns = `id, tenant_id, name, secret_hash, scopes, rate_limit,
	created_at, created_by, expires_at, revoked_at, last_used_at`

func scanServiceAPIKey(sc rowScanner) (*models.ServiceAPIKey, error) {
	var (
		key        models.ServiceAPIKey
		scopes     []byte
		expiresAt  sql.NullTime
		revokedAt  sql.NullTime
		lastUsedAt sql.NullTime
	)

	if err := sc.Scan(&key.ID, &key.TenantID, &key.Name, &key.SecretHash, &scopes, &key.RateLimit,
		&key.CreatedAt, &key.CreatedBy, &expiresAt, &revokedAt, &lastUsedAt); err != nil {
		return nil, err
	}

	if len(scopes) > 0 {
		if err := json.Unmarshal(scopes, &key.Scopes); err != nil {
			return nil, fmt.Errorf("decode scopes for api key %s: %w", key.ID, err)
		}
	}
	if expiresAt.Valid {
		key.ExpiresAt = &expiresAt.Time
	}
	if revokedAt.Valid {
		key.RevokedAt = &revokedAt.Time
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = &lastUsedAt.Time
	}

	return &key, nil
}

// StoreServiceAPIKey persists an issued key. There is no expiry on the row
// itself: a key that has expired or been revoked is still worth keeping so it
// can be listed, and so a request bearing it is refused with a reason rather
// than as an unknown id.
func (s *Store) StoreServiceAPIKey(ctx context.Context, key *models.ServiceAPIKey) error {
	db, err := s.database()
	if err != nil {
		return err
	}

	scopes, err := marshalJSONArray(key.Scopes)
	if err != nil {
		return fmt.Errorf("encode scopes: %w", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO tenant_api_keys (id, tenant_id, name, secret_hash, scopes, rate_limit,
			created_at, created_by, expires_at, revoked_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			tenant_id = EXCLUDED.tenant_id,
			name = EXCLUDED.name,
			secret_hash = EXCLUDED.secret_hash,
			scopes = EXCLUDED.scopes,
			rate_limit = EXCLUDED.rate_limit,
			created_by = EXCLUDED.created_by,
			expires_at = EXCLUDED.expires_at,
			revoked_at = EXCLUDED.revoked_at,
			last_used_at = EXCLUDED.last_used_at`,
		key.ID, key.TenantID, key.Name, key.SecretHash, scopes, key.RateLimit,
		key.CreatedAt, key.CreatedBy, nullableTime(key.ExpiresAt), nullableTime(key.RevokedAt),
		nullableTime(key.LastUsedAt))
	return err
}

// GetServiceAPIKey loads a key by its public id — the id is what a request
// presents, so it is what the lookup is keyed on.
func (s *Store) GetServiceAPIKey(ctx context.Context, id string) (*models.ServiceAPIKey, error) {
	db, err := s.database()
	if err != nil {
		return nil, err
	}

	key, err := scanServiceAPIKey(db.QueryRowContext(ctx,
		`SELECT `+apiKeyColumns+` FROM tenant_api_keys WHERE id = $1`, id))
	if err == sql.ErrNoRows {
		return nil, ErrAPIKeyNotFound
	}
	return key, err
}

// ListServiceAPIKeys returns every issued key, newest first.
func (s *Store) ListServiceAPIKeys(ctx context.Context) ([]*models.ServiceAPIKey, error) {
	return s.queryServiceAPIKeys(ctx, `SELECT `+apiKeyColumns+` FROM tenant_api_keys ORDER BY created_at DESC`)
}

// ListServiceAPIKeysByTenant narrows the listing to one holder.
func (s *Store) ListServiceAPIKeysByTenant(ctx context.Context, tenantID string) ([]*models.ServiceAPIKey, error) {
	return s.queryServiceAPIKeys(ctx,
		`SELECT `+apiKeyColumns+` FROM tenant_api_keys WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
}

func (s *Store) queryServiceAPIKeys(ctx context.Context, query string, args ...any) ([]*models.ServiceAPIKey, error) {
	db, err := s.database()
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]*models.ServiceAPIKey, 0)
	for rows.Next() {
		key, err := scanServiceAPIKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// RevokeServiceAPIKey marks a key unusable. It is idempotent, and it keeps the
// record so that the revocation stays visible in the admin listing.
func (s *Store) RevokeServiceAPIKey(ctx context.Context, id string) (*models.ServiceAPIKey, error) {
	db, err := s.database()
	if err != nil {
		return nil, err
	}

	key, err := scanServiceAPIKey(db.QueryRowContext(ctx,
		`UPDATE tenant_api_keys SET revoked_at = $2
		 WHERE id = $1 AND revoked_at IS NULL
		 RETURNING `+apiKeyColumns, id, time.Now().UTC()))
	if err == sql.ErrNoRows {
		// Either unknown or already revoked; the read tells the two apart.
		return s.GetServiceAPIKey(ctx, id)
	}
	return key, err
}

// RevokeServiceAPIKeysByTenant revokes every key one holder has. This is the
// incident-response path: a single call, rather than reading the listing and
// revoking ids by hand while the credential is still live.
//
// A failure part way through does not discard the work already done — the keys
// that were revoked come back alongside the error, because during an incident
// "which ones are dead" is the question that matters.
func (s *Store) RevokeServiceAPIKeysByTenant(ctx context.Context, tenantID string) ([]*models.ServiceAPIKey, error) {
	keys, err := s.ListServiceAPIKeysByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	revoked := make([]*models.ServiceAPIKey, 0, len(keys))
	var failed error
	for _, key := range keys {
		updated, err := s.RevokeServiceAPIKey(ctx, key.ID)
		if err != nil {
			failed = err
			continue
		}
		revoked = append(revoked, updated)
	}
	return revoked, failed
}

// TouchServiceAPIKey records that a key was just used. Only last_used_at is
// written, so concurrent requests bearing the same credential cannot lose each
// other's changes to the rest of the record.
func (s *Store) TouchServiceAPIKey(ctx context.Context, id string) error {
	db, err := s.database()
	if err != nil {
		return err
	}

	_, err = db.ExecContext(ctx,
		`UPDATE tenant_api_keys SET last_used_at = $2 WHERE id = $1`, id, time.Now().UTC())
	return err
}

// DeleteServiceAPIKey removes a key outright. Prefer revocation: this leaves
// no trace that the credential ever existed.
func (s *Store) DeleteServiceAPIKey(ctx context.Context, id string) error {
	db, err := s.database()
	if err != nil {
		return err
	}

	_, err = db.ExecContext(ctx, `DELETE FROM tenant_api_keys WHERE id = $1`, id)
	return err
}

// marshalJSONArray encodes a slice for a JSONB column, turning nil into an
// empty array rather than the JSON null a nil slice would otherwise produce.
func marshalJSONArray(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if len(encoded) == 0 || string(encoded) == "null" {
		return "[]", nil
	}
	return string(encoded), nil
}
