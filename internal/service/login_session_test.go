package service

import (
	"context"
	"testing"
	"time"

	"garde/internal/models"
	"garde/internal/testutil"
	"garde/pkg/crypto"
	pkgerrors "garde/pkg/errors"
	"garde/pkg/session"
)

// Login → ValidateSession → Logout through miniredis. Covers the core
// session lifecycle without touching MFA/OTP branches.
func newSessionService(t *testing.T) *AuthService {
	t.Helper()
	testutil.InitConfig(t, map[string]string{"superuser_email": "root@example.com"})
	return NewAuthService(testutil.NewTestStore(t))
}

func seedLoginUser(t *testing.T, s *AuthService, email, password string, status models.UserStatus) *models.User {
	t.Helper()
	hash, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	u := &models.User{
		ID:           "user-" + email,
		Email:        email,
		PasswordHash: hash,
		Status:       status,
	}
	if err := s.repo.StoreUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestLoginValidateLogout(t *testing.T) {
	s := newSessionService(t)
	ctx := context.Background()
	seedLoginUser(t, s, "user@example.com", "DevAdminTest123!", models.UserStatusOk)

	resp, err := s.Login(ctx, &models.LoginRequest{Email: "user@example.com", Password: "DevAdminTest123!"}, "10.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if len(resp.SessionID) != 86 {
		t.Fatalf("session id len = %d, want 86", len(resp.SessionID))
	}

	valid, err := s.ValidateSession(ctx, resp.SessionID, "10.0.0.1", "test-agent")
	if err != nil || valid == nil || !valid.Response.Valid {
		t.Fatalf("validate = %+v, %v", valid, err)
	}
	if valid.CookieMaxAge <= 0 {
		t.Fatalf("CookieMaxAge = %v, want sliding TTL > 0", valid.CookieMaxAge)
	}

	// A different IP trips the multiple-IP guard, which blacklists and
	// deletes the session — so exercise it on a separate session.
	resp2, err := s.Login(ctx, &models.LoginRequest{Email: "user@example.com", Password: "DevAdminTest123!"}, "10.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	badIP, err := s.ValidateSession(ctx, resp2.SessionID, "10.0.0.2", "test-agent")
	if err != nil {
		t.Fatalf("wrong-ip validate errored: %v", err)
	}
	if badIP != nil && badIP.Response.Valid {
		t.Fatal("session valid from a different IP")
	}

	if err := s.Logout(ctx, resp.SessionID); err != nil {
		t.Fatalf("logout: %v", err)
	}
	after, err := s.ValidateSession(ctx, resp.SessionID, "10.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("post-logout validate errored: %v", err)
	}
	if after != nil && after.Response.Valid {
		t.Fatal("session still valid after logout")
	}
}

func TestValidateSessionAbsoluteExpiry(t *testing.T) {
	s := newSessionService(t)
	ctx := context.Background()
	testutil.InitConfig(t, map[string]string{
		"superuser_email":          "root@example.com",
		"session_idle_timeout":     "1h",
		"session_absolute_timeout": "2h",
	})
	seedLoginUser(t, s, "abs@example.com", "DevAdminTest123!", models.UserStatusOk)
	resp, err := s.Login(ctx, &models.LoginRequest{Email: "abs@example.com", Password: "DevAdminTest123!"}, "10.0.0.1", "ua")
	if err != nil {
		t.Fatal(err)
	}
	data, err := s.repo.GetSessionData(ctx, resp.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	data.CreatedAt = time.Now().Add(-3 * time.Hour)
	if err := s.repo.StoreSessionData(ctx, resp.SessionID, data, session.IdleTimeout()); err != nil {
		t.Fatal(err)
	}
	expired, err := s.ValidateSession(ctx, resp.SessionID, "10.0.0.1", "ua")
	if err != nil {
		t.Fatal(err)
	}
	if expired != nil && expired.Response.Valid {
		t.Fatal("session past absolute timeout still valid")
	}
}

func TestLoginRejectsTable(t *testing.T) {
	s := newSessionService(t)
	ctx := context.Background()
	seedLoginUser(t, s, "locked@example.com", "DevAdminTest123!", models.UserStatusLockedByAdmin)
	seedLoginUser(t, s, "pending@example.com", "DevAdminTest123!", models.UserStatusPendingApproval)
	seedLoginUser(t, s, "ok@example.com", "DevAdminTest123!", models.UserStatusOk)

	cases := []struct {
		name  string
		email string
		pw    string
		want  string
	}{
		{"unknown", "nobody@example.com", "DevAdminTest123!", pkgerrors.ErrAuthFailed},
		{"wrong password", "ok@example.com", "WrongPassword1!", pkgerrors.ErrAuthFailed},
		{"locked", "locked@example.com", "DevAdminTest123!", pkgerrors.ErrAuthFailed},
		{"pending", "pending@example.com", "DevAdminTest123!", pkgerrors.ErrAuthFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.Login(ctx, &models.LoginRequest{Email: tc.email, Password: tc.pw}, "10.0.0.1", "ua")
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoginMFARequiredWithoutCode(t *testing.T) {
	s := newSessionService(t)
	ctx := context.Background()
	u := seedLoginUser(t, s, "mfa@example.com", "DevAdminTest123!", models.UserStatusOk)
	// The MFA secret is encrypted at rest, so the key must be configured
	// before the store that writes it.
	testutil.InitConfig(t, map[string]string{
		"superuser_email":    "root@example.com",
		"mfa_encryption_key": "test-key-for-unit-tests",
	})
	fresh, err := s.repo.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	fresh.MFAEnabled = true
	fresh.MFASecret = "JBSWY3DPEHPK3PXP"
	if err := s.repo.StoreUser(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	_, err = s.Login(ctx, &models.LoginRequest{Email: "mfa@example.com", Password: "DevAdminTest123!"}, "10.0.0.1", "ua")
	if err == nil || err.Error() != pkgerrors.ErrMFARequired {
		t.Fatalf("err = %v, want %q", err, pkgerrors.ErrMFARequired)
	}
}
