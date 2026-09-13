package service

import (
	"context"
	"testing"

	"garde/internal/models"
	pkgerrors "garde/pkg/errors"
)

// Superuser UpdateUser paths that do not need the permissions catalogue
// (permRepo stays nil in unit tests, so catalogue branches are asserted as
// NotLoaded errors rather than exercised).
func newUpdateService(t *testing.T) *AuthService {
	t.Helper()
	return newFlowService(t, baseSecrets())
}

func seedPair(t *testing.T, s *AuthService) (admin, target *models.User) {
	t.Helper()
	ctx := context.Background()
	admin = &models.User{ID: "su-admin", Email: "su-admin@example.com", Status: models.UserStatusOk}
	target = &models.User{ID: "su-target", Email: "su-target@example.com", Status: models.UserStatusOk}
	for _, u := range []*models.User{admin, target} {
		if err := s.repo.StoreUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	return admin, target
}

func statusPtr(s models.UserStatus) *models.UserStatus { return &s }
func boolPtr(b bool) *bool                             { return &b }

func TestUpdateUserGuards(t *testing.T) {
	s := newUpdateService(t)
	ctx := context.Background()
	admin, target := seedPair(t, s)

	if err := s.UpdateUser(ctx, "ghost", target.ID, &models.UpdateUserRequest{}, true, false); err == nil ||
		err.Error() != pkgerrors.ErrOperationFailed {
		t.Fatalf("unknown admin err = %v", err)
	}
	if err := s.UpdateUser(ctx, admin.ID, "ghost", &models.UpdateUserRequest{}, true, false); err == nil ||
		err.Error() != pkgerrors.ErrUserNotFound {
		t.Fatalf("unknown target err = %v", err)
	}
	if err := s.UpdateUser(ctx, admin.ID, target.ID, &models.UpdateUserRequest{}, false, false); err == nil ||
		err.Error() != pkgerrors.ErrUnauthorized {
		t.Fatalf("plain caller err = %v", err)
	}
	super := &models.User{ID: "su-root", Email: "root@example.com", Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, super); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUser(ctx, admin.ID, super.ID, &models.UpdateUserRequest{}, false, true); err == nil ||
		err.Error() != pkgerrors.ErrUnauthorized {
		t.Fatalf("superuser target err = %v", err)
	}
}

func TestUpdateUserStatusAndMFAAsSuperuser(t *testing.T) {
	s := newUpdateService(t)
	ctx := context.Background()
	admin, target := seedPair(t, s)

	if err := s.UpdateUser(ctx, admin.ID, target.ID, &models.UpdateUserRequest{
		Status: statusPtr(models.UserStatusLockedByAdmin),
	}, true, false); err != nil {
		t.Fatalf("lock: %v", err)
	}
	got, _ := s.repo.GetUserByID(ctx, target.ID)
	if got.Status != models.UserStatusLockedByAdmin {
		t.Fatalf("status = %q", got.Status)
	}

	if err := s.UpdateUser(ctx, admin.ID, target.ID, &models.UpdateUserRequest{
		Status:      statusPtr(models.UserStatusOk),
		MFAEnforced: boolPtr(true),
	}, true, false); err != nil {
		t.Fatalf("unlock+enforce: %v", err)
	}
	got, _ = s.repo.GetUserByID(ctx, target.ID)
	if got.Status != models.UserStatusOk || !got.MFAEnforced {
		t.Fatalf("after = %+v", got)
	}
}

func TestUpdateUserApproveRejectPending(t *testing.T) {
	s := newUpdateService(t)
	ctx := context.Background()
	admin, target := seedPair(t, s)

	// Approve with no pending request is a harmless store.
	if err := s.UpdateUser(ctx, admin.ID, target.ID, &models.UpdateUserRequest{ApproveUpdate: true}, true, false); err != nil {
		t.Fatalf("approve empty: %v", err)
	}

	// Reject clears a pending request without touching anything else.
	target, err := s.repo.GetUserByID(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	target.PendingUpdates = &models.UserUpdateRequest{Fields: models.UserUpdateFields{
		GroupsAdd: []models.UserGroup{"g"},
	}}
	if err := s.repo.StoreUser(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUser(ctx, admin.ID, target.ID, &models.UpdateUserRequest{RejectUpdate: true}, true, false); err != nil {
		t.Fatalf("reject: %v", err)
	}
	got, _ := s.repo.GetUserByID(ctx, target.ID)
	if got.PendingUpdates != nil {
		t.Fatal("pending updates survive rejection")
	}
	if got.Status != models.UserStatusOk {
		t.Fatalf("reject changed status to %q", got.Status)
	}

	// Catalogue-backed paths report NotLoaded instead of touching data.
	target, err = s.repo.GetUserByID(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	target.PendingUpdates = &models.UserUpdateRequest{Fields: models.UserUpdateFields{
		GroupsAdd: []models.UserGroup{"g"},
	}}
	if err := s.repo.StoreUser(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUser(ctx, admin.ID, target.ID, &models.UpdateUserRequest{ApproveUpdate: true}, true, false); err == nil ||
		err.Error() != pkgerrors.ErrGroupsNotLoaded {
		t.Fatalf("approve groups err = %v", err)
	}
	if err := s.UpdateUser(ctx, admin.ID, target.ID, &models.UpdateUserRequest{
		Permissions: &map[models.Permission]bool{"read": true},
	}, true, false); err == nil || err.Error() != pkgerrors.ErrPermissionsNotLoaded {
		t.Fatalf("direct permissions err = %v", err)
	}
	if err := s.UpdateUser(ctx, admin.ID, target.ID, &models.UpdateUserRequest{
		Groups: &map[models.UserGroup]bool{"g": true},
	}, true, false); err == nil || err.Error() != pkgerrors.ErrGroupsNotLoaded {
		t.Fatalf("direct groups err = %v", err)
	}
}
