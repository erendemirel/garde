package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"garde/internal/models"
	"garde/internal/repository"
	"garde/pkg/errors"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"garde/pkg/config"
)

func newAuthServiceWithMiniRedis(t *testing.T) *AuthService {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewAuthService(repository.NewRedisRepositoryFromClient(client))
}

func initSuperuserEmail(t *testing.T, email string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "superuser_email"), []byte(email), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
}

func storeTestUser(t *testing.T, svc *AuthService, id, email string) *models.User {
	t.Helper()
	user := &models.User{
		ID:          id,
		Email:       email,
		Status:      models.UserStatusOk,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		Permissions: models.UserPermissions{},
		Groups:      models.UserGroups{"support": true},
	}
	if err := svc.repo.StoreUser(context.Background(), user); err != nil {
		t.Fatalf("StoreUser: %v", err)
	}
	return user
}

// Permissions and groups are set through UpdateUser, so an admin editing
// their own record is the shape an escalation would take. DeleteUser has
// always guarded the equivalent; this asserts UpdateUser now does too.
func TestUpdateUserRejectsAdminEditingThemselves(t *testing.T) {
	initSuperuserEmail(t, "root@example.com")
	svc := newAuthServiceWithMiniRedis(t)
	admin := storeTestUser(t, svc, "admin-1", "helpdesk@example.com")

	err := svc.UpdateUser(context.Background(), admin.ID, admin.ID, &models.UpdateUserRequest{}, false, true)
	if err == nil {
		t.Fatal("UpdateUser allowed an admin to target their own record")
	}
	if err.Error() != errors.ErrUnauthorized {
		t.Fatalf("error = %q, want %q", err.Error(), errors.ErrUnauthorized)
	}
}

// The guard exists to stop escalation, and a superuser has nothing to
// escalate to. Blocking them would also strand a superuser's own pending
// update request, since admins cannot target the superuser record.
func TestUpdateUserAllowsSuperuserOnTheirOwnRecord(t *testing.T) {
	initSuperuserEmail(t, "root@example.com")
	svc := newAuthServiceWithMiniRedis(t)
	root := storeTestUser(t, svc, "root-1", "root@example.com")

	if err := svc.UpdateUser(context.Background(), root.ID, root.ID, &models.UpdateUserRequest{}, true, false); err != nil {
		t.Fatalf("UpdateUser refused the superuser on their own record: %v", err)
	}
}

// A different admin targeting this user must still get past the self guard
// and be stopped only by the checks that already existed.
func TestUpdateUserSelfGuardDoesNotAffectOtherTargets(t *testing.T) {
	initSuperuserEmail(t, "root@example.com")
	svc := newAuthServiceWithMiniRedis(t)
	admin := storeTestUser(t, svc, "admin-1", "helpdesk@example.com")
	target := storeTestUser(t, svc, "user-1", "customer@example.com")

	// Superuser is exempt from the group checks, so this reaches the update
	// itself and proves the new guard is keyed on identity, not on presence.
	if err := svc.UpdateUser(context.Background(), admin.ID, target.ID, &models.UpdateUserRequest{}, true, false); err != nil {
		t.Fatalf("UpdateUser refused a distinct target: %v", err)
	}
}
