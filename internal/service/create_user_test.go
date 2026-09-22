package service

import (
	"context"
	"testing"

	"garde/internal/models"
	"garde/internal/testutil"
	pkgerrors "garde/pkg/errors"
)

// CreateUser is covered here (not the audit-sensitive login/session paths):
// opaque-success enumeration defence, superuser block, validation.
func newCreateUserService(t *testing.T, secrets map[string]string) *AuthService {
	t.Helper()
	testutil.InitConfig(t, secrets)
	return NewAuthService(testutil.NewTestStore(t))
}

func TestCreateUserSuccessIsPending(t *testing.T) {
	s := newCreateUserService(t, map[string]string{
		"superuser_email":            "root@example.com",
		"require_admin_approval":     "true",
		"require_email_verification": "false",
	})
	resp, err := s.CreateUser(context.Background(), &models.CreateUserRequest{
		Email:    "new@example.com",
		Password: "DevAdminTest123!",
	})
	if err != nil || resp.UserID == "" {
		t.Fatalf("resp = %+v, err = %v", resp, err)
	}
	got, err := s.repo.GetUserByEmail(context.Background(), "new@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.UserStatusPendingApproval {
		t.Fatalf("status = %q, want pending approval", got.Status)
	}
	if resp.Next != "await_admin" {
		t.Fatalf("next = %q, want await_admin", resp.Next)
	}
	if got.ID != resp.UserID {
		t.Fatal("returned id does not match stored user")
	}
}

func TestCreateUserDuplicateLooksLikeSuccess(t *testing.T) {
	s := newCreateUserService(t, map[string]string{
		"superuser_email":            "root@example.com",
		"require_admin_approval":     "true",
		"require_email_verification": "false",
	})
	ctx := context.Background()
	first, err := s.CreateUser(ctx, &models.CreateUserRequest{Email: "dup@example.com", Password: "DevAdminTest123!"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateUser(ctx, &models.CreateUserRequest{Email: "dup@example.com", Password: "DevAdminTest123!"})
	if err != nil {
		t.Fatalf("duplicate must look like success, got %v", err)
	}
	if second.UserID == "" || second.UserID == first.UserID {
		t.Fatal("duplicate must return a fresh random id, not the real one")
	}
	// Original record untouched.
	stored, err := s.repo.GetUserByEmail(ctx, "dup@example.com")
	if err != nil || stored.ID != first.UserID {
		t.Fatalf("stored = %+v, %v", stored, err)
	}
}

func TestCreateUserSuperuserBlocked(t *testing.T) {
	s := newCreateUserService(t, map[string]string{
		"superuser_email":            "root@example.com",
		"require_admin_approval":     "true",
		"require_email_verification": "false",
	})
	_, err := s.CreateUser(context.Background(), &models.CreateUserRequest{
		Email:    "root@example.com",
		Password: "DevAdminTest123!",
	})
	if err == nil || err.Error() != pkgerrors.ErrUnauthorized {
		t.Fatalf("err = %v, want %q", err, pkgerrors.ErrUnauthorized)
	}
}

func TestCreateUserAdminEmailOpaque(t *testing.T) {
	s := newCreateUserService(t, map[string]string{
		"superuser_email":            "root@example.com",
		"admin_users_json":           `{"admin@example.com":"AdminTest123!"}`,
		"require_admin_approval":     "true",
		"require_email_verification": "false",
	})
	resp, err := s.CreateUser(context.Background(), &models.CreateUserRequest{
		Email:    "admin@example.com",
		Password: "DevAdminTest123!",
	})
	if err != nil || resp.UserID == "" {
		t.Fatalf("admin email must look like success: %+v, %v", resp, err)
	}
	if _, err := s.repo.GetUserByEmail(context.Background(), "admin@example.com"); err == nil {
		t.Fatal("no user record must be created for admin emails")
	}
}

func TestCreateUserEmptyPassword(t *testing.T) {
	s := newCreateUserService(t, map[string]string{
		"superuser_email":            "root@example.com",
		"require_admin_approval":     "true",
		"require_email_verification": "false",
	})
	if _, err := s.CreateUser(context.Background(), &models.CreateUserRequest{Email: "x@example.com"}); err == nil {
		t.Fatal("empty password accepted")
	}
}
