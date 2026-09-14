package repository

import (
	"context"
	"database/sql"
	"time"

	"garde/internal/models"
)

const patColumns = `id, user_id, name, secret_hash, created_at, expires_at, revoked_at, last_used_at`

func scanPAT(sc rowScanner) (*models.PersonalAccessToken, error) {
	var (
		token      models.PersonalAccessToken
		expiresAt  sql.NullTime
		revokedAt  sql.NullTime
		lastUsedAt sql.NullTime
	)

	if err := sc.Scan(&token.ID, &token.UserID, &token.Name, &token.SecretHash,
		&token.CreatedAt, &expiresAt, &revokedAt, &lastUsedAt); err != nil {
		return nil, err
	}

	if expiresAt.Valid {
		token.ExpiresAt = &expiresAt.Time
	}
	if revokedAt.Valid {
		token.RevokedAt = &revokedAt.Time
	}
	if lastUsedAt.Valid {
		token.LastUsedAt = &lastUsedAt.Time
	}

	return &token, nil
}

// StorePAT writes an issued token. It upserts so that re-storing a token the
// caller has just read is not an error.
func (s *Store) StorePAT(ctx context.Context, token *models.PersonalAccessToken) error {
	db, err := s.database()
	if err != nil {
		return err
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO personal_access_tokens (id, user_id, name, secret_hash, created_at, expires_at, revoked_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			secret_hash = EXCLUDED.secret_hash,
			expires_at = EXCLUDED.expires_at,
			revoked_at = EXCLUDED.revoked_at,
			last_used_at = EXCLUDED.last_used_at`,
		token.ID, token.UserID, token.Name, token.SecretHash, token.CreatedAt,
		nullableTime(token.ExpiresAt), nullableTime(token.RevokedAt), nullableTime(token.LastUsedAt))
	return err
}

// GetPAT resolves a token by the public id a caller presents. Revoked and
// expired tokens still resolve, so authentication can refuse them with a
// reason rather than as an unknown id.
func (s *Store) GetPAT(ctx context.Context, id string) (*models.PersonalAccessToken, error) {
	db, err := s.database()
	if err != nil {
		return nil, err
	}

	token, err := scanPAT(db.QueryRowContext(ctx, `SELECT `+patColumns+` FROM personal_access_tokens WHERE id = $1`, id))
	if err == sql.ErrNoRows {
		return nil, ErrPATNotFound
	}
	return token, err
}

// ListPATsByUser returns the user's active (non-revoked) tokens, newest first.
// Revoked rows are kept but excluded here; a presented secret still resolves
// through GetPAT and is refused as revoked.
func (s *Store) ListPATsByUser(ctx context.Context, userID string) ([]*models.PersonalAccessToken, error) {
	db, err := s.database()
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx,
		`SELECT `+patColumns+` FROM personal_access_tokens
		 WHERE user_id = $1 AND revoked_at IS NULL
		 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tokens := make([]*models.PersonalAccessToken, 0)
	for rows.Next() {
		token, err := scanPAT(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

// CountPATsByUser counts tokens that still consume the per-user cap — active
// ones only. Revoked entries must not count, or issue/revoke cycles would
// permanently lock the user out at MaxPATsPerUser.
func (s *Store) CountPATsByUser(ctx context.Context, userID string) (int, error) {
	db, err := s.database()
	if err != nil {
		return 0, err
	}

	var count int
	err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM personal_access_tokens WHERE user_id = $1 AND revoked_at IS NULL`, userID).
		Scan(&count)
	return count, err
}

// RevokePAT marks one of the user's tokens unusable. It is idempotent, and it
// keeps the row so the revocation stays visible.
func (s *Store) RevokePAT(ctx context.Context, id, userID string) (*models.PersonalAccessToken, error) {
	db, err := s.database()
	if err != nil {
		return nil, err
	}

	// The user_id predicate is part of the lookup, not a check afterwards: one
	// user must not be able to learn that another user's token id exists.
	token, err := scanPAT(db.QueryRowContext(ctx,
		`SELECT `+patColumns+` FROM personal_access_tokens WHERE id = $1 AND user_id = $2`, id, userID))
	if err == sql.ErrNoRows {
		return nil, ErrPATNotFound
	}
	if err != nil {
		return nil, err
	}
	if token.Revoked() {
		return token, nil
	}

	revoked, err := scanPAT(db.QueryRowContext(ctx,
		`UPDATE personal_access_tokens SET revoked_at = $3
		 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
		 RETURNING `+patColumns, id, userID, time.Now().UTC()))
	if err == sql.ErrNoRows {
		// Revoked by a concurrent caller between the read and the write.
		return s.GetPAT(ctx, id)
	}
	return revoked, err
}

// TouchPAT records that a token was just used. A missing row is not an error:
// this runs on the authentication path, where the token has already been
// judged, and a revoke landing concurrently must not fail the request.
func (s *Store) TouchPAT(ctx context.Context, id string) error {
	db, err := s.database()
	if err != nil {
		return err
	}

	_, err = db.ExecContext(ctx,
		`UPDATE personal_access_tokens SET last_used_at = $2 WHERE id = $1`, id, time.Now().UTC())
	return err
}

// RevokeAllPATsByUser marks every active PAT for the user as revoked.
func (s *Store) RevokeAllPATsByUser(ctx context.Context, userID string) error {
	db, err := s.database()
	if err != nil {
		return err
	}

	_, err = db.ExecContext(ctx,
		`UPDATE personal_access_tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`,
		userID, time.Now().UTC())
	return err
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return *value
}
