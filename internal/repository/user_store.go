package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"garde/internal/models"
	"garde/pkg/crypto"
	"garde/pkg/session"
	"garde/pkg/validation"
)

// Column order is shared by every read path so scanUser stays the single place
// that knows the row shape. "groups" is quoted because it reads as a keyword.
const userColumns = `id, email, password_hash, mfa_secret_encrypted, mfa_enabled, mfa_enforced,
	status, permissions, "groups", pending_updates, last_login, created_at, updated_at`

type rowScanner interface {
	Scan(dest ...any) error
}

// scanUser reads one row and restores the two fields that are not stored as
// plain columns: the MFA secret is decrypted, and the JSONB blobs are decoded.
func scanUser(sc rowScanner) (*models.User, error) {
	var (
		user        models.User
		status      string
		mfaSecret   sql.NullString
		permissions []byte
		groups      []byte
		pending     []byte
		lastLogin   sql.NullTime
	)

	if err := sc.Scan(
		&user.ID, &user.Email, &user.PasswordHash, &mfaSecret, &user.MFAEnabled, &user.MFAEnforced,
		&status, &permissions, &groups, &pending, &lastLogin, &user.CreatedAt, &user.UpdatedAt,
	); err != nil {
		return nil, err
	}

	user.Status = models.UserStatus(status)
	if lastLogin.Valid {
		user.LastLogin = lastLogin.Time
	}

	if len(permissions) > 0 {
		if err := json.Unmarshal(permissions, &user.Permissions); err != nil {
			return nil, fmt.Errorf("decode permissions for user %s: %w", user.ID, err)
		}
	}
	if len(groups) > 0 {
		if err := json.Unmarshal(groups, &user.Groups); err != nil {
			return nil, fmt.Errorf("decode groups for user %s: %w", user.ID, err)
		}
	}
	if len(pending) > 0 && string(pending) != "null" {
		var updates models.UserUpdateRequest
		if err := json.Unmarshal(pending, &updates); err != nil {
			return nil, fmt.Errorf("decode pending updates for user %s: %w", user.ID, err)
		}
		user.PendingUpdates = &updates
	}

	if mfaSecret.Valid && mfaSecret.String != "" {
		plain, err := crypto.DecryptString(mfaSecret.String)
		if err != nil {
			return nil, fmt.Errorf("decrypt MFA secret: %w", err)
		}
		user.MFASecret = plain
	}

	return &user, nil
}

// StoreUser creates or updates an account under the same optimistic-concurrency
// rule the Redis implementation enforced: a write whose UpdatedAt is older than
// what is already stored is refused rather than allowed to clobber it.
//
// The row is locked for the duration so the read and the write cannot be
// interleaved by another writer; the UpdatedAt guard on the UPDATE itself is
// what turns a lost race into ErrConcurrentUpdate instead of silent data loss.
func (s *Store) StoreUser(ctx context.Context, user *models.User) error {
	db, err := s.database()
	if err != nil {
		return err
	}

	user.Email = validation.NormalizeEmail(user.Email)

	permissions, err := marshalJSONObject(user.Permissions)
	if err != nil {
		return fmt.Errorf("encode permissions: %w", err)
	}
	groups, err := marshalJSONObject(user.Groups)
	if err != nil {
		return fmt.Errorf("encode groups: %w", err)
	}

	var pending any
	if user.PendingUpdates != nil {
		encoded, err := json.Marshal(user.PendingUpdates)
		if err != nil {
			return fmt.Errorf("encode pending updates: %w", err)
		}
		pending = string(encoded)
	}

	var mfaSecret any
	if user.MFASecret != "" {
		encrypted, err := crypto.EncryptString(user.MFASecret)
		if err != nil {
			return fmt.Errorf("encrypt MFA secret: %w", err)
		}
		mfaSecret = encrypted
	}

	var lastLogin any
	if !user.LastLogin.IsZero() {
		lastLogin = user.LastLogin
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var storedUpdatedAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT updated_at FROM users WHERE id = $1 FOR UPDATE`, user.ID).
		Scan(&storedUpdatedAt)

	switch {
	case err == sql.ErrNoRows:
		if user.CreatedAt.IsZero() {
			user.CreatedAt = time.Now().UTC()
		}
		user.UpdatedAt = time.Now().UTC()

		_, err = tx.ExecContext(ctx, `
			INSERT INTO users (id, email, password_hash, mfa_secret_encrypted, mfa_enabled, mfa_enforced,
				status, permissions, "groups", pending_updates, last_login, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			user.ID, user.Email, user.PasswordHash, mfaSecret, user.MFAEnabled, user.MFAEnforced,
			string(user.Status), permissions, groups, pending, lastLogin, user.CreatedAt, user.UpdatedAt)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrEmailAlreadyExists
			}
			return err
		}

	case err != nil:
		return err

	default:
		if storedUpdatedAt.After(user.UpdatedAt) {
			return ErrConcurrentUpdate
		}
		user.UpdatedAt = time.Now().UTC()

		// password_hash / mfa_secret_encrypted / last_login keep their stored
		// values when the caller omits them: partial updates must not blank
		// credentials or timestamps. created_at is immutable and deliberately
		// absent from the SET list. Intentional MFA wipe goes through
		// ClearUserMFASecret (DisableMFA). pending_updates still accepts NULL
		// so approve/reject can clear a request.
		result, err := tx.ExecContext(ctx, `
			UPDATE users SET
				email = $2,
				password_hash = COALESCE(NULLIF($3, ''), password_hash),
				mfa_secret_encrypted = COALESCE($4, mfa_secret_encrypted),
				mfa_enabled = $5,
				mfa_enforced = $6,
				status = $7,
				permissions = $8,
				"groups" = $9,
				pending_updates = $10,
				last_login = COALESCE($11, last_login),
				updated_at = $12
			WHERE id = $1 AND updated_at = $13`,
			user.ID, user.Email, user.PasswordHash, mfaSecret, user.MFAEnabled, user.MFAEnforced,
			string(user.Status), permissions, groups, pending, lastLogin, user.UpdatedAt, storedUpdatedAt)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrEmailAlreadyExists
			}
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return ErrConcurrentUpdate
		}
	}

	return tx.Commit()
}

// ClearUserMFASecret wipes the encrypted MFA secret. StoreUser treats an empty
// MFASecret as "leave unchanged", so DisableMFA (and tests that assert a wipe)
// call this after flipping MFAEnabled off.
func (s *Store) ClearUserMFASecret(ctx context.Context, userID string) error {
	db, err := s.database()
	if err != nil {
		return err
	}
	result, err := db.ExecContext(ctx,
		`UPDATE users SET mfa_secret_encrypted = NULL, updated_at = $2 WHERE id = $1`,
		userID, time.Now().UTC())
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errUserNotFound
	}
	return nil
}

func (s *Store) GetUserByID(ctx context.Context, userID string) (*models.User, error) {
	db, err := s.database()
	if err != nil {
		return nil, err
	}

	user, err := scanUser(db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, userID))
	if err == sql.ErrNoRows {
		return nil, errUserNotFound
	}
	return user, err
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	db, err := s.database()
	if err != nil {
		return nil, err
	}

	// lower(email) matches the unique index, so the lookup uses it rather than
	// scanning, and a record stored before normalisation still resolves.
	user, err := scanUser(db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE lower(email) = $1`, validation.NormalizeEmail(email)))
	if err == sql.ErrNoRows {
		return nil, errUserNotFound
	}
	return user, err
}

// DeleteUser removes the account and everything the schema cascades from it
// (its personal access tokens), then revokes live sessions and clears the
// user's ephemeral Redis state. The Redis half is best-effort: the account is
// already gone, and the keys it touches all expire on their own — but sessions
// are blacklisted first so a held session id cannot validate until TTL.
func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	db, err := s.database()
	if err != nil {
		return err
	}

	result, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errUserNotFound
	}

	if client := s.getClient(); client != nil {
		// Enumerate before dropping the index so each session:{id} is
		// blacklisted and deleted, matching revokeAllUserSessions.
		if sessions, err := s.GetUserActiveSessions(ctx, userID); err != nil {
			slog.Warn("Failed to list sessions for deleted user", "user_id", userID, "error", err)
		} else {
			for _, sessionID := range sessions {
				if err := s.BlacklistSession(ctx, sessionID, session.BlacklistDuration); err != nil {
					slog.Warn("Failed to blacklist session for deleted user",
						"user_id", userID, "session_id_prefix", session.IDPrefix(sessionID), "error", err)
				}
				if err := s.DeleteSession(ctx, sessionID); err != nil {
					slog.Warn("Failed to delete session for deleted user",
						"user_id", userID, "session_id_prefix", session.IDPrefix(sessionID), "error", err)
				}
			}
		}

		pipe := client.Pipeline()
		pipe.Del(ctx, tempMFAKey(userID))
		pipe.Del(ctx, userSessionsKey(userID))
		pipe.Del(ctx, requestWindowKey(userID))
		pipe.Del(ctx, auditLogKey(userID))
		pipe.Del(ctx, otpKey(userID))
		pipe.Del(ctx, resetAttemptsKey(userID))
		pipe.Del(ctx, securityCodeKeyPrefix+userID)
		pipe.Del(ctx, lastRequestKey(userID))
		pipe.Del(ctx, suspiciousActivityKey(userID))
		if _, err := pipe.Exec(ctx); err != nil {
			slog.Warn("Failed to clear ephemeral state for deleted user", "user_id", userID, "error", err)
		}
	}

	return nil
}

func (s *Store) GetAllUsers(ctx context.Context) ([]*models.User, error) {
	return s.queryUsers(ctx, `SELECT `+userColumns+` FROM users ORDER BY created_at`)
}

// GetLockedUsers returns every account that is not in the ok state — locked,
// pending approval, or rejected.
func (s *Store) GetLockedUsers(ctx context.Context) ([]*models.User, error) {
	return s.queryUsers(ctx,
		`SELECT `+userColumns+` FROM users WHERE status <> $1 ORDER BY created_at`,
		string(models.UserStatusOk))
}

// queryUsers skips rows it cannot decode rather than failing the whole listing:
// one account with an unreadable MFA secret must not hide every other account
// from an admin trying to find it.
func (s *Store) queryUsers(ctx context.Context, query string, args ...any) ([]*models.User, error) {
	db, err := s.database()
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			slog.Warn("Skipping unreadable user row", "error", err)
			continue
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

// marshalJSONObject encodes a map for a JSONB column, turning a nil map into
// an empty object rather than the JSON null a nil map would otherwise produce.
func marshalJSONObject(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if len(encoded) == 0 || string(encoded) == "null" {
		return "{}", nil
	}
	return string(encoded), nil
}
