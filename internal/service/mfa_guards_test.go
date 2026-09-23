package service

import (
	"context"
	"testing"
	"time"

	"garde/internal/models"
	"garde/pkg/crypto"
	pkgerrors "garde/pkg/errors"

	"github.com/pquerna/otp/totp"
)

// MFA-gated login and password change against a user whose secret was
// enrolled directly (same shape VerifyAndEnableMFA produces).
func seedMFAUser(t *testing.T, s *AuthService, id, email string) (string, *models.User) {
	t.Helper()
	ctx := context.Background()
	hash, err := crypto.HashPassword("DevAdminTest123!")
	if err != nil {
		t.Fatal(err)
	}
	u := &models.User{ID: id, Email: email, PasswordHash: hash, Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	u, err = s.repo.GetUserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "JBSWY3DPEHPK3PXP"
	u.MFAEnabled = true
	u.MFASecret = secret
	if err := s.repo.StoreUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	stored, err := s.repo.GetUserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return secret, stored
}

func TestLoginWithMFACodeTable(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	secret, _ := seedMFAUser(t, s, "mfa-login", "mfa-login@example.com")

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, &models.LoginRequest{
		Email: "mfa-login@example.com", Password: "DevAdminTest123!", MFACode: code,
	}, "10.0.0.1", "ua"); err != nil {
		t.Fatalf("valid MFA login: %v", err)
	}
	if _, err := s.Login(ctx, &models.LoginRequest{
		Email: "mfa-login@example.com", Password: "DevAdminTest123!", MFACode: "000000",
	}, "10.0.0.1", "ua"); err == nil || err.Error() != pkgerrors.ErrInvalidMFACode {
		t.Fatalf("wrong code err = %v, want %q", err, pkgerrors.ErrInvalidMFACode)
	}
}

func TestChangePasswordWithMFA(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	secret, user := seedMFAUser(t, s, "mfa-cp", "mfa-cp@example.com")

	if err := s.ChangePassword(ctx, user.ID, &models.ChangePasswordRequest{
		OldPassword: "DevAdminTest123!", NewPassword: "NewPassword1!",
	}); err == nil || err.Error() != pkgerrors.ErrMFARequired {
		t.Fatalf("missing code err = %v, want %q", err, pkgerrors.ErrMFARequired)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(ctx, user.ID, &models.ChangePasswordRequest{
		OldPassword: "DevAdminTest123!", NewPassword: "NewPassword1!", MFACode: code,
	}); err != nil {
		t.Fatalf("change with MFA: %v", err)
	}
}

func TestGetCurrentUserFiltersWithoutCatalogue(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	user := &models.User{
		ID: "filter-1", Email: "filter@example.com", Status: models.UserStatusOk,
		Permissions: models.UserPermissions{"read": true},
		Groups:      models.UserGroups{"eng": true},
	}
	if err := s.repo.StoreUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCurrentUser(ctx, "filter-1")
	if err != nil {
		t.Fatal(err)
	}
	// permRepo is nil in unit tests, so no permission is visible: enabled
	// entries filter down to nothing instead of leaking.
	if len(got.Permissions) != 0 {
		t.Fatalf("permissions = %v, want empty without catalogue", got.Permissions)
	}
	if !got.Groups["eng"] {
		t.Fatal("groups must pass through unfiltered")
	}
}

func TestListAndGetUserAdminNeedGroups(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	admin := &models.User{ID: "admin-g", Email: "admin-g@example.com", Status: models.UserStatusOk,
		Groups: models.UserGroups{"eng": true}}
	target := &models.User{ID: "target-g", Email: "target-g@example.com", Status: models.UserStatusOk,
		Groups: models.UserGroups{"eng": true}}
	for _, u := range []*models.User{admin, target} {
		if err := s.repo.StoreUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ListUsers(ctx, admin.ID, false, true); err == nil ||
		err.Error() != pkgerrors.ErrGroupsNotLoaded {
		t.Fatalf("list err = %v, want %q", err, pkgerrors.ErrGroupsNotLoaded)
	}
	if _, err := s.GetUser(ctx, admin.ID, target.ID, false, true); err == nil ||
		err.Error() != pkgerrors.ErrGroupsNotLoaded {
		t.Fatalf("get err = %v, want %q", err, pkgerrors.ErrGroupsNotLoaded)
	}
}

func TestLogoutUnknownSession(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	if err := s.Logout(context.Background(), "no-such-session"); err == nil {
		t.Fatal("logout of unknown session succeeds")
	}
}

func TestDisableMFALocksAfterTooManyBadCodes(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	_, user := seedMFAUser(t, s, "mfa-lock", "mfa-lock@example.com")

	for i := 0; i < maxMFAAttempts; i++ {
		err := s.DisableMFA(ctx, user.ID, "000000")
		if err == nil || err.Error() != pkgerrors.ErrInvalidMFACode {
			t.Fatalf("attempt %d: err = %v, want %q", i+1, err, pkgerrors.ErrInvalidMFACode)
		}
	}
	err := s.DisableMFA(ctx, user.ID, "000000")
	if err == nil || err.Error() != pkgerrors.ErrTooManyAttempts {
		t.Fatalf("lock attempt: err = %v, want %q", err, pkgerrors.ErrTooManyAttempts)
	}
	stored, err := s.repo.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != models.UserStatusLockedBySecurity {
		t.Fatalf("status = %q, want locked by security", stored.Status)
	}
}
