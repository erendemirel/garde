package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"garde/internal/models"
	"garde/pkg/crypto"
	pkgerrors "garde/pkg/errors"
	"garde/pkg/session"
)

// Brute-force lockout: five bad passwords trip recordFailedAuth, which locks
// the account and blocks the IP. The sixth attempt then fails on status.
func TestLoginLocksAfterThreshold(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	hash, err := crypto.HashPassword("RightPassword1!")
	if err != nil {
		t.Fatal(err)
	}
	user := &models.User{ID: "brute-1", Email: "brute@example.com", PasswordHash: hash, Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 4; i++ {
		_, err := s.Login(ctx, &models.LoginRequest{Email: "brute@example.com", Password: "WrongPassword1!"}, "10.9.9.9", "ua")
		if err == nil || err.Error() != pkgerrors.ErrAuthFailed {
			t.Fatalf("attempt %d err = %v, want %q", i, err, pkgerrors.ErrAuthFailed)
		}
	}
	_, err = s.Login(ctx, &models.LoginRequest{Email: "brute@example.com", Password: "WrongPassword1!"}, "10.9.9.9", "ua")
	if err == nil || err.Error() != pkgerrors.ErrAccessRestricted {
		t.Fatalf("attempt 5 err = %v, want %q", err, pkgerrors.ErrAccessRestricted)
	}
	stored, _ := s.repo.GetUserByID(ctx, "brute-1")
	if stored.Status != models.UserStatusLockedBySecurity {
		t.Fatalf("status = %q, want locked by security", stored.Status)
	}
	blocked, err := s.repo.IsIPBlocked(ctx, "10.9.9.9")
	if err != nil || !blocked {
		t.Fatalf("blocked = %v, %v; want true", blocked, err)
	}
	// Even the right password is refused while locked.
	_, err = s.Login(ctx, &models.LoginRequest{Email: "brute@example.com", Password: "RightPassword1!"}, "10.9.9.9", "ua")
	if err == nil || err.Error() != pkgerrors.ErrAccessRestricted {
		t.Fatalf("locked login err = %v, want %q", err, pkgerrors.ErrAccessRestricted)
	}
}

func TestValidateSessionForServiceTable(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	hash, err := crypto.HashPassword("RightPassword1!")
	if err != nil {
		t.Fatal(err)
	}
	user := &models.User{ID: "svc-1", Email: "svc@example.com", PasswordHash: hash, Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	resp, err := s.Login(ctx, &models.LoginRequest{Email: "svc@example.com", Password: "RightPassword1!"}, "10.0.0.1", "ua")
	if err != nil {
		t.Fatal(err)
	}

	valid, err := s.ValidateSessionForService(ctx, resp.SessionID)
	if err != nil || valid == nil || !valid.Response.Valid || valid.UserID != "svc-1" {
		t.Fatalf("valid = %+v, %v", valid, err)
	}
	// No IP/UA binding by design: other origins still validate.
	valid, err = s.ValidateSessionForService(ctx, resp.SessionID)
	if err != nil || !valid.Response.Valid {
		t.Fatalf("repeat = %+v, %v", valid, err)
	}

	unknown, err := s.ValidateSessionForService(ctx, strings.Repeat("B", 86))
	if err != nil || unknown == nil || unknown.Response.Valid {
		t.Fatalf("unknown = %+v, %v; want invalid", unknown, err)
	}

	// Blacklisted sessions read invalid.
	if err := s.repo.BlacklistSession(ctx, resp.SessionID, session.BlacklistDuration); err != nil {
		t.Fatal(err)
	}
	blacklisted, err := s.ValidateSessionForService(ctx, resp.SessionID)
	if err != nil || blacklisted.Response.Valid {
		t.Fatalf("blacklisted = %+v, %v; want invalid", blacklisted, err)
	}

	// Expired sessions read invalid and are reaped (past absolute max).
	old := &session.SessionData{UserID: "svc-1", IP: "h", UserAgent: "u", CreatedAt: time.Now().Add(-25 * time.Hour)}
	if err := s.repo.StoreSessionData(ctx, strings.Repeat("C", 86), old, session.IdleTimeout()); err != nil {
		t.Fatal(err)
	}
	expired, err := s.ValidateSessionForService(ctx, strings.Repeat("C", 86))
	if err != nil || expired.Response.Valid {
		t.Fatalf("expired = %+v, %v; want invalid", expired, err)
	}

	// Locked users fail even with a live session.
	fresh, err := s.Login(ctx, &models.LoginRequest{Email: "svc@example.com", Password: "RightPassword1!"}, "10.0.0.1", "ua")
	if err != nil {
		t.Fatal(err)
	}
	user.Status = models.UserStatusLockedByAdmin
	user.UpdatedAt = time.Now()
	if err := s.repo.StoreUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	locked, err := s.ValidateSessionForService(ctx, fresh.SessionID)
	if err != nil || locked.Response.Valid {
		t.Fatalf("locked user = %+v, %v; want invalid", locked, err)
	}
}

func TestServiceUserLockPassthrough(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	ok, err := s.AcquireUserLock(ctx, "u-1", time.Minute)
	if err != nil || !ok {
		t.Fatalf("acquire = %v, %v", ok, err)
	}
	if err := s.ReleaseUserLock(ctx, "u-1"); err != nil {
		t.Fatalf("release: %v", err)
	}
}
