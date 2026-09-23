package repository

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"garde/internal/models"
	"garde/pkg/session"
)

// Durable user tests need Postgres; session/OTP/lock paths stay Redis-only.
func newUserRepo(t *testing.T) *RedisRepository {
	t.Helper()
	return newDurableStore(t)
}

func newEphemeralRepo(t *testing.T) *RedisRepository {
	t.Helper()
	return NewRedisRepositoryFromClient(newMiniRedisClient(t))
}

func TestStoreAndGetUserRoundTrip(t *testing.T) {
	ctx := context.Background()
	r := newUserRepo(t)
	now := time.Now()
	u := &models.User{
		ID:           "u-1",
		Email:        "a@example.com",
		PasswordHash: "HASH",
		Status:       models.UserStatusOk,
		CreatedAt:    now,
		UpdatedAt:    now,
		Permissions:  models.UserPermissions{"read": true},
		Groups:       models.UserGroups{"eng": true},
	}
	if err := r.StoreUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	byEmail, err := r.GetUserByEmail(ctx, "a@example.com")
	if err != nil || byEmail.ID != "u-1" || byEmail.PasswordHash != "HASH" {
		t.Fatalf("by email = %+v, %v", byEmail, err)
	}
	byID, err := r.GetUserByID(ctx, "u-1")
	if err != nil || byID.Email != "a@example.com" {
		t.Fatalf("by id = %+v, %v", byID, err)
	}
	// Password hash lives in its own column, not inside JSONB blobs.
	db := r.DB()
	var perms, groups []byte
	if err := db.QueryRowContext(ctx, `SELECT permissions, "groups" FROM users WHERE id = $1`, "u-1").Scan(&perms, &groups); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(perms), "HASH") || strings.Contains(string(groups), "HASH") {
		t.Fatalf("hash inside JSONB: permissions=%s groups=%s", perms, groups)
	}
	if _, err := r.GetUserByEmail(ctx, "missing@example.com"); err == nil {
		t.Fatal("missing email returns nil error")
	}
}

func TestStoreUserDuplicateEmail(t *testing.T) {
	ctx := context.Background()
	r := newUserRepo(t)
	mk := func(id, email string) *models.User {
		return &models.User{ID: id, Email: email, Status: models.UserStatusOk}
	}
	if err := r.StoreUser(ctx, mk("u-1", "dup@example.com")); err != nil {
		t.Fatal(err)
	}
	if err := r.StoreUser(ctx, mk("u-2", "dup@example.com")); !errors.Is(err, ErrEmailAlreadyExists) {
		t.Fatalf("err = %v, want ErrEmailAlreadyExists", err)
	}
	// Original mapping untouched.
	got, err := r.GetUserByEmail(ctx, "dup@example.com")
	if err != nil || got.ID != "u-1" {
		t.Fatalf("after conflict = %+v, %v", got, err)
	}
}

func TestUserMFASecretRoundTrip(t *testing.T) {
	initTestConfig(t, map[string]string{"mfa_encryption_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="})
	ctx := context.Background()
	r := newUserRepo(t)
	u := &models.User{ID: "u-mfa", Email: "mfa@example.com", Status: models.UserStatusOk, MFASecret: "JBSWY3DPEHPK3PXP"}
	if err := r.StoreUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetUserByID(ctx, "u-mfa")
	if err != nil || got.MFASecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("mfa round-trip = %+v, %v", got, err)
	}
	// Stored form must be encrypted, not plaintext.
	var enc string
	if err := r.DB().QueryRowContext(ctx, `SELECT mfa_secret_encrypted FROM users WHERE id = $1`, "u-mfa").Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if enc == "JBSWY3DPEHPK3PXP" || enc == "" {
		t.Fatalf("stored mfa = %q", enc)
	}

	// Empty MFASecret on StoreUser must not wipe enrollment.
	got.MFASecret = ""
	got.Email = "mfa-renamed@example.com"
	got.UpdatedAt = time.Now()
	if err := r.StoreUser(ctx, got); err != nil {
		t.Fatal(err)
	}
	again, err := r.GetUserByID(ctx, "u-mfa")
	if err != nil || again.MFASecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("empty MFASecret wiped enrollment: %+v, %v", again, err)
	}
	if again.Email != "mfa-renamed@example.com" {
		t.Fatalf("email = %q", again.Email)
	}

	if err := r.ClearUserMFASecret(ctx, "u-mfa"); err != nil {
		t.Fatal(err)
	}
	cleared, err := r.GetUserByID(ctx, "u-mfa")
	if err != nil || cleared.MFASecret != "" {
		t.Fatalf("ClearUserMFASecret = %+v, %v", cleared, err)
	}
}

func TestDeleteUserBlacklistsLiveSessions(t *testing.T) {
	ctx := context.Background()
	r := newUserRepo(t)
	u := &models.User{ID: "u-del", Email: "del@example.com", Status: models.UserStatusOk}
	if err := r.StoreUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	data := &session.SessionData{UserID: "u-del", IP: "h", UserAgent: "ua", CreatedAt: time.Now()}
	if err := r.StoreSessionData(ctx, "sess-del", data, time.Hour); err != nil {
		t.Fatal(err)
	}

	if err := r.DeleteUser(ctx, "u-del"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetSessionData(ctx, "sess-del"); err == nil {
		t.Fatal("session key still readable after DeleteUser")
	}
	banned, err := r.IsSessionBlacklisted(ctx, "sess-del")
	if err != nil || !banned {
		t.Fatalf("blacklist after DeleteUser = %v, %v", banned, err)
	}
}

func TestSessionStoreGetDelete(t *testing.T) {
	ctx := context.Background()
	r := newEphemeralRepo(t)
	data := &session.SessionData{UserID: "u-1", IP: "h", UserAgent: "ua", CreatedAt: time.Now()}
	if err := r.StoreSessionData(ctx, "sess-1", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetSessionData(ctx, "sess-1")
	if err != nil || got.UserID != "u-1" {
		t.Fatalf("get = %+v, %v", got, err)
	}
	if err := r.BlacklistSession(ctx, "sess-1", time.Hour); err != nil {
		t.Fatal(err)
	}
	blacklisted, err := r.IsSessionBlacklisted(ctx, "sess-1")
	if err != nil || !blacklisted {
		t.Fatalf("blacklisted = %v, %v", blacklisted, err)
	}
	if err := r.DeleteSession(ctx, "sess-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetSessionData(ctx, "sess-1"); err == nil {
		t.Fatal("deleted session still readable")
	}
	// Blacklist must survive DeleteSession so revocation bans persist.
	stillBanned, err := r.IsSessionBlacklisted(ctx, "sess-1")
	if err != nil || !stillBanned {
		t.Fatalf("blacklist after delete = %v, %v; want still blacklisted", stillBanned, err)
	}
}

func TestOTPStoreGetDeleteAndAttempts(t *testing.T) {
	ctx := context.Background()
	r := newEphemeralRepo(t)
	if err := r.StoreOTP(ctx, "u-1", "HASHED"); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetOTP(ctx, "u-1")
	if err != nil || got != "HASHED" {
		t.Fatalf("otp = %q, %v", got, err)
	}
	for want := 1; want <= 3; want++ {
		n, err := r.TrackResetAttempt(ctx, "u-1")
		if err != nil || n != want {
			t.Fatalf("attempt %d: n=%d err=%v", want, n, err)
		}
	}
	if err := r.DeleteOTP(ctx, "u-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetOTP(ctx, "u-1"); err == nil {
		t.Fatal("deleted OTP still readable")
	}
}

func TestEmailVerifyAttemptTracking(t *testing.T) {
	ctx := context.Background()
	r := newEphemeralRepo(t)
	for want := 1; want <= 3; want++ {
		n, err := r.TrackEmailVerifyAttempt(ctx, "u-verify")
		if err != nil || n != want {
			t.Fatalf("attempt %d: n=%d err=%v", want, n, err)
		}
	}
	if err := r.ClearEmailVerifyAttempts(ctx, "u-verify"); err != nil {
		t.Fatal(err)
	}
	n, err := r.TrackEmailVerifyAttempt(ctx, "u-verify")
	if err != nil || n != 1 {
		t.Fatalf("after clear: n=%d err=%v, want 1", n, err)
	}
}

func TestMFAAttemptAndOTPSendTracking(t *testing.T) {
	ctx := context.Background()
	r := newEphemeralRepo(t)
	for want := 1; want <= 2; want++ {
		n, err := r.TrackMFAAttempt(ctx, "u-mfa")
		if err != nil || n != want {
			t.Fatalf("mfa attempt %d: n=%d err=%v", want, n, err)
		}
	}
	if err := r.ClearMFAAttempts(ctx, "u-mfa"); err != nil {
		t.Fatal(err)
	}
	n, err := r.TrackMFAAttempt(ctx, "u-mfa")
	if err != nil || n != 1 {
		t.Fatalf("mfa after clear: n=%d err=%v", n, err)
	}
	for want := 1; want <= 2; want++ {
		n, err := r.TrackOTPSend(ctx, "u-otp")
		if err != nil || n != want {
			t.Fatalf("otp send %d: n=%d err=%v", want, n, err)
		}
	}
	if OTPSendMax() < 1 {
		t.Fatal("OTPSendMax must be positive")
	}
}

func TestUserLockAcquireRelease(t *testing.T) {
	ctx := context.Background()
	r := newEphemeralRepo(t)
	ok, err := r.AcquireUserLock(ctx, "u-1", time.Minute)
	if err != nil || !ok {
		t.Fatalf("first acquire = %v, %v", ok, err)
	}
	ok, err = r.AcquireUserLock(ctx, "u-1", time.Minute)
	if err != nil || ok {
		t.Fatalf("second acquire = %v, %v; want held", ok, err)
	}
	if err := r.ReleaseUserLock(ctx, "u-1"); err != nil {
		t.Fatal(err)
	}
	if ok, err := r.AcquireUserLock(ctx, "u-1", time.Minute); err != nil || !ok {
		t.Fatalf("after release = %v, %v", ok, err)
	}
}

func TestDeleteUserRemovesIndex(t *testing.T) {
	ctx := context.Background()
	r := newUserRepo(t)
	u := &models.User{ID: "u-del", Email: "del@example.com", Status: models.UserStatusOk}
	if err := r.StoreUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteUser(ctx, "u-del"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetUserByID(ctx, "u-del"); err == nil {
		t.Fatal("deleted user still readable by id")
	}
	if _, err := r.GetUserByEmail(ctx, "del@example.com"); err == nil {
		t.Fatal("deleted user still readable by email")
	}
}

func TestStoreUserEmailChangeMovesIndex(t *testing.T) {
	ctx := context.Background()
	r := newUserRepo(t)
	u := &models.User{ID: "u-mv", Email: "old@example.com", Status: models.UserStatusOk}
	if err := r.StoreUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	// Re-read so UpdatedAt is current, then change only the email.
	u, err := r.GetUserByID(ctx, "u-mv")
	if err != nil {
		t.Fatal(err)
	}
	u.Email = "new@example.com"
	if err := r.StoreUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if got, err := r.GetUserByEmail(ctx, "new@example.com"); err != nil || got.ID != "u-mv" {
		t.Fatalf("new index = %+v, %v", got, err)
	}
	if _, err := r.GetUserByEmail(ctx, "old@example.com"); err == nil {
		t.Fatal("stale email index still resolves")
	}
}
