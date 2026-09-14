package service

import (
	"context"
	"testing"

	"garde/internal/models"
	"garde/internal/testutil"
)

func newBootstrapService(t *testing.T, secrets map[string]string) *AuthService {
	t.Helper()
	testutil.InitConfig(t, secrets)
	return NewAuthService(testutil.NewTestStore(t))
}

func TestInitializeSuperUserCreatesAndRefreshes(t *testing.T) {
	s := newBootstrapService(t, map[string]string{
		"superuser_email":    "root@example.com",
		"superuser_password": "DevAdminTest123!",
	})
	ctx := context.Background()

	if err := InitializeSuperUser(ctx, s.repo); err != nil {
		t.Fatalf("create: %v", err)
	}
	user, err := s.repo.GetUserByEmail(ctx, "root@example.com")
	if err != nil || user.Status != models.UserStatusOk {
		t.Fatalf("stored = %+v, %v", user, err)
	}
	firstID := user.ID

	// Re-running with a rotated password refreshes the same record.
	testutil.InitConfig(t, map[string]string{
		"superuser_email":    "root@example.com",
		"superuser_password": "RotatedPassword1!",
	})
	if err := InitializeSuperUser(ctx, s.repo); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	refreshed, _ := s.repo.GetUserByEmail(ctx, "root@example.com")
	if refreshed.ID != firstID {
		t.Fatal("refresh created a second superuser record")
	}
	if _, err := s.Login(ctx, &models.LoginRequest{Email: "root@example.com", Password: "RotatedPassword1!"}, "10.0.0.1", "ua"); err != nil {
		t.Fatalf("login with rotated password: %v", err)
	}
}

func TestInitializeSuperUserMissingSecrets(t *testing.T) {
	s := newBootstrapService(t, map[string]string{})
	if err := InitializeSuperUser(context.Background(), s.repo); err == nil {
		t.Fatal("expected error with no superuser secrets")
	}
}

func TestInitializeAdminUsersCreatesAndSkips(t *testing.T) {
	s := newBootstrapService(t, map[string]string{
		"superuser_email":  "root@example.com",
		"admin_users_json": `{"admin@example.com":"DevAdminTest123!"}`,
	})
	ctx := context.Background()
	if err := InitializeAdminUsers(ctx, s.repo); err != nil {
		t.Fatalf("create: %v", err)
	}
	admin, err := s.repo.GetUserByEmail(ctx, "admin@example.com")
	if err != nil || admin.Status != models.UserStatusOk {
		t.Fatalf("stored = %+v, %v", admin, err)
	}
	// Idempotent re-run.
	if err := InitializeAdminUsers(ctx, s.repo); err != nil {
		t.Fatalf("re-run: %v", err)
	}
}

func TestInitializeAdminUsersEmptyAndSuperuserEntry(t *testing.T) {
	s := newBootstrapService(t, map[string]string{"superuser_email": "root@example.com"})
	if err := InitializeAdminUsers(context.Background(), s.repo); err != nil {
		t.Fatalf("empty map: %v", err)
	}
	// An entry naming the superuser is skipped, not created as an admin.
	s2 := newBootstrapService(t, map[string]string{
		"superuser_email":  "root@example.com",
		"admin_users_json": `{"root@example.com":"DevAdminTest123!"}`,
	})
	if err := InitializeAdminUsers(context.Background(), s2.repo); err != nil {
		t.Fatalf("superuser entry: %v", err)
	}
	if _, err := s2.repo.GetUserByEmail(context.Background(), "root@example.com"); err == nil {
		t.Fatal("superuser email must not gain an admin record")
	}
}
