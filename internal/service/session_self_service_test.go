package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"garde/internal/models"
	"garde/pkg/crypto"
	pkgerrors "garde/pkg/errors"

	"github.com/pquerna/otp/totp"
)

func TestListAndRevokeOwnSessions(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	hash, err := crypto.HashPassword("DevAdminTest123!")
	if err != nil {
		t.Fatal(err)
	}
	user := &models.User{ID: "sess-u1", Email: "sess@example.com", PasswordHash: hash, Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	a, err := s.Login(ctx, &models.LoginRequest{Email: "sess@example.com", Password: "DevAdminTest123!"}, "10.1.1.1", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Login(ctx, &models.LoginRequest{Email: "sess@example.com", Password: "DevAdminTest123!"}, "10.2.2.2", "Mozilla/5.0 (Macintosh) Firefox/121.0")
	if err != nil {
		t.Fatal(err)
	}
	_ = b

	listed, err := s.ListSessions(ctx, user.ID, a.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(listed.Sessions))
	}
	var current, other *models.SessionInfo
	for i := range listed.Sessions {
		info := &listed.Sessions[i]
		if info.Current {
			current = info
		} else {
			other = info
		}
		if info.ID == "" || info.ID == a.SessionID || info.ID == b.SessionID {
			t.Fatalf("public id must be opaque, got %q", info.ID)
		}
		if info.IPDisplay == "" || info.UASummary == "" || info.ApproxPlace == "" {
			t.Fatalf("missing display fields: %+v", info)
		}
	}
	if current == nil || other == nil {
		t.Fatal("expected current and other")
	}
	if !strings.HasPrefix(current.IPDisplay, "10.") {
		t.Fatalf("ip display = %q", current.IPDisplay)
	}

	revokedCurrent, err := s.RevokeOwnSession(ctx, user.ID, a.SessionID, other.ID, "")
	if err != nil || revokedCurrent {
		t.Fatalf("revoke other = %v, %v", revokedCurrent, err)
	}
	listed, err = s.ListSessions(ctx, user.ID, a.SessionID)
	if err != nil || len(listed.Sessions) != 1 || !listed.Sessions[0].Current {
		t.Fatalf("after revoke other: %+v, %v", listed, err)
	}

	cSess, err := s.Login(ctx, &models.LoginRequest{Email: "sess@example.com", Password: "DevAdminTest123!"}, "10.3.3.3", "curl/8.0")
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.RevokeOtherSessions(ctx, user.ID, a.SessionID, "")
	if err != nil || n < 1 {
		t.Fatalf("revoke others = %d, %v", n, err)
	}
	got, err := s.ValidateSession(ctx, cSess.SessionID, "10.3.3.3", "curl/8.0")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil && got.Response.Valid {
		t.Fatal("revoked session still valid")
	}
	still, err := s.ValidateSession(ctx, a.SessionID, "10.1.1.1", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0")
	if err != nil || still == nil || !still.Response.Valid {
		t.Fatalf("current session should remain: %+v, %v", still, err)
	}
}

func TestRevokeOwnSessionRequiresMFAWhenEnabled(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	secret, user := seedMFAUser(t, s, "sess-mfa", "sess-mfa@example.com")

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Login(ctx, &models.LoginRequest{
		Email: user.Email, Password: "DevAdminTest123!", MFACode: code,
	}, "10.4.4.4", "Mozilla/5.0 Chrome/1.0")
	if err != nil {
		t.Fatal(err)
	}
	code2, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, &models.LoginRequest{
		Email: user.Email, Password: "DevAdminTest123!", MFACode: code2,
	}, "10.5.5.5", "Mozilla/5.0 Firefox/1.0"); err != nil {
		t.Fatal(err)
	}

	listed, err := s.ListSessions(ctx, user.ID, a.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	var otherID string
	for _, info := range listed.Sessions {
		if !info.Current {
			otherID = info.ID
			break
		}
	}
	if otherID == "" {
		t.Fatal("no other session")
	}

	_, err = s.RevokeOwnSession(ctx, user.ID, a.SessionID, otherID, "")
	if err == nil || err.Error() != pkgerrors.ErrMFARequired {
		t.Fatalf("err = %v, want MFA required", err)
	}
	_, err = s.RevokeOtherSessions(ctx, user.ID, a.SessionID, "")
	if err == nil || err.Error() != pkgerrors.ErrMFARequired {
		t.Fatalf("revoke-others err = %v, want MFA required", err)
	}

	code3, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.RevokeOwnSession(ctx, user.ID, a.SessionID, otherID, code3)
	if err != nil {
		t.Fatalf("revoke with MFA: %v", err)
	}
}

func TestLoginEnforcesSessionMaxActive(t *testing.T) {
	s := newFlowService(t, map[string]string{
		"superuser_email":       "root@example.com",
		"mfa_encryption_key":    "test-key-for-unit-tests",
		"session_max_active":    "2",
	})
	ctx := context.Background()
	hash, err := crypto.HashPassword("DevAdminTest123!")
	if err != nil {
		t.Fatal(err)
	}
	user := &models.User{ID: "cap-u1", Email: "cap@example.com", PasswordHash: hash, Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	first, err := s.Login(ctx, &models.LoginRequest{Email: "cap@example.com", Password: "DevAdminTest123!"}, "10.1.0.1", "ua-1")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	second, err := s.Login(ctx, &models.LoginRequest{Email: "cap@example.com", Password: "DevAdminTest123!"}, "10.1.0.2", "ua-2")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	third, err := s.Login(ctx, &models.LoginRequest{Email: "cap@example.com", Password: "DevAdminTest123!"}, "10.1.0.3", "ua-3")
	if err != nil {
		t.Fatal(err)
	}

	listed, err := s.ListSessions(ctx, user.ID, third.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Sessions) != 2 {
		t.Fatalf("active sessions = %d, want 2", len(listed.Sessions))
	}
	got, err := s.ValidateSession(ctx, first.SessionID, "10.1.0.1", "ua-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil && got.Response.Valid {
		t.Fatal("oldest session should have been revoked")
	}
	still, err := s.ValidateSession(ctx, second.SessionID, "10.1.0.2", "ua-2")
	if err != nil || still == nil || !still.Response.Valid {
		t.Fatalf("second session should remain: %+v, %v", still, err)
	}
	cur, err := s.ValidateSession(ctx, third.SessionID, "10.1.0.3", "ua-3")
	if err != nil || cur == nil || !cur.Response.Valid {
		t.Fatalf("newest session should remain: %+v, %v", cur, err)
	}
}
