package repository

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"garde/internal/models"
	"garde/internal/testutil"
	"garde/pkg/session"
)

func newUserRepo(t *testing.T) *RedisRepository {
	t.Helper()
	_, client := testutil.NewMiniRedis(t)
	return NewRedisRepositoryFromClient(client)
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
	// Password hash must not leak into the user JSON blob itself.
	raw, err := r.getClient().Get(ctx, "user:u-1").Result()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "HASH") {
		t.Fatalf("hash inside user JSON: %s", raw)
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
	testutil.InitConfig(t, map[string]string{"mfa_encryption_key": "test-key-for-unit-tests"})
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
	enc, err := r.getClient().Get(ctx, "user_mfa:u-mfa").Result()
	if err != nil || enc == "JBSWY3DPEHPK3PXP" || enc == "" {
		t.Fatalf("stored mfa = %q, %v", enc, err)
	}
}

func TestSessionStoreGetDelete(t *testing.T) {
	ctx := context.Background()
	r := newUserRepo(t)
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
	r := newUserRepo(t)
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

func TestUserLockAcquireRelease(t *testing.T) {
	ctx := context.Background()
	r := newUserRepo(t)
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
