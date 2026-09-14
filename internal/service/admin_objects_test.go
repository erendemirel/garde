package service

import (
	"context"
	"testing"

	"garde/internal/models"
	pkgerrors "garde/pkg/errors"
)

// Admin-object flows through miniredis: superuser paths plus every guard.
// Admin shared-group paths need the groups system loaded (Postgres-backed),
// so they stay with the integration suite; guards are asserted here.
func newAdminService(t *testing.T) *AuthService {
	t.Helper()
	return newFlowService(t, baseSecrets())
}

func seedAdminTarget(t *testing.T, s *AuthService) (admin, target *models.User) {
	t.Helper()
	ctx := context.Background()
	admin = &models.User{ID: "admin-x", Email: "admin-x@example.com", Status: models.UserStatusOk}
	target = &models.User{ID: "target-x", Email: "target-x@example.com", Status: models.UserStatusOk}
	for _, u := range []*models.User{admin, target} {
		if err := s.repo.StoreUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	return admin, target
}

func TestDeleteUserGuardsAndSuperuserPath(t *testing.T) {
	s := newAdminService(t)
	ctx := context.Background()
	admin, target := seedAdminTarget(t, s)

	if err := s.DeleteUser(ctx, admin.ID, target.ID, true, false); err != nil {
		t.Fatalf("superuser delete: %v", err)
	}
	if _, err := s.repo.GetUserByID(ctx, target.ID); err == nil {
		t.Fatal("target still present after delete")
	}

	// Fresh target for the guard cases.
	target2 := &models.User{ID: "target-y", Email: "target-y@example.com", Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, target2); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name              string
		adminID, targetID string
		isSuper, isAdmin  bool
		want              string
	}{
		{"plain caller refused", admin.ID, target2.ID, false, false, pkgerrors.ErrUnauthorized},
		{"self delete refused", admin.ID, admin.ID, true, false, pkgerrors.ErrUnauthorized},
		{"unknown target", admin.ID, "ghost", true, false, pkgerrors.ErrUserNotFound},
		{"unknown admin", "ghost", target2.ID, true, false, pkgerrors.ErrUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.DeleteUser(ctx, tc.adminID, tc.targetID, tc.isSuper, tc.isAdmin)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}

	// Non-superuser cannot delete the superuser record.
	super := &models.User{ID: "root-x", Email: "root@example.com", Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, super); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, admin.ID, super.ID, false, true); err == nil ||
		err.Error() != pkgerrors.ErrUnauthorized {
		t.Fatalf("superuser target err = %v, want %q", err, pkgerrors.ErrUnauthorized)
	}
}

func TestGetUserGuardsAndSuperuserPath(t *testing.T) {
	s := newAdminService(t)
	ctx := context.Background()
	admin, target := seedAdminTarget(t, s)

	got, err := s.GetUser(ctx, admin.ID, target.ID, true, false)
	if err != nil || got.Email != target.Email {
		t.Fatalf("superuser get = %+v, %v", got, err)
	}
	if _, err := s.GetUser(ctx, admin.ID, target.ID, false, false); err == nil ||
		err.Error() != pkgerrors.ErrUnauthorized {
		t.Fatalf("plain caller err = %v, want %q", err, pkgerrors.ErrUnauthorized)
	}
	if _, err := s.GetUser(ctx, admin.ID, "ghost", true, false); err == nil ||
		err.Error() != pkgerrors.ErrUserNotFound {
		t.Fatalf("unknown target err = %v, want %q", err, pkgerrors.ErrUserNotFound)
	}
}

func TestRevokeUserSessionGuardsAndSuperuserPath(t *testing.T) {
	s := newAdminService(t)
	ctx := context.Background()
	admin, target := seedAdminTarget(t, s)

	if err := s.RevokeUserSession(ctx, admin.ID, target.ID, "", true, false); err != nil {
		t.Fatalf("superuser revoke: %v", err)
	}
	if err := s.RevokeUserSession(ctx, admin.ID, "ghost", "", true, false); err == nil ||
		err.Error() != pkgerrors.ErrUserNotFound {
		t.Fatalf("unknown target err = %v, want %q", err, pkgerrors.ErrUserNotFound)
	}
	if err := s.RevokeUserSession(ctx, admin.ID, target.ID, "", false, false); err == nil ||
		err.Error() != pkgerrors.ErrUnauthorized {
		t.Fatalf("plain caller err = %v, want %q", err, pkgerrors.ErrUnauthorized)
	}
	// MFA-gated admin without a code is refused before any revocation.
	mfaAdmin := &models.User{ID: "admin-mfa", Email: "admin-mfa@example.com", Status: models.UserStatusOk, MFAEnabled: true, MFASecret: "JBSWY3DPEHPK3PXP"}
	if err := s.repo.StoreUser(ctx, mfaAdmin); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeUserSession(ctx, mfaAdmin.ID, target.ID, "", false, true); err == nil ||
		err.Error() != pkgerrors.ErrMFARequired {
		t.Fatalf("mfa-gated err = %v, want %q", err, pkgerrors.ErrMFARequired)
	}
}

func TestRequestUpdateGuards(t *testing.T) {
	s := newAdminService(t)
	ctx := context.Background()
	user := &models.User{ID: "req-1", Email: "req@example.com", Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	super := &models.User{ID: "root-r", Email: "root@example.com", Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, super); err != nil {
		t.Fatal(err)
	}

	if err := s.RequestUpdate(ctx, "req-1", nil); err == nil ||
		err.Error() != pkgerrors.ErrInvalidRequest {
		t.Fatalf("nil req err = %v, want %q", err, pkgerrors.ErrInvalidRequest)
	}
	if err := s.RequestUpdate(ctx, "ghost", &models.RequestUpdateRequest{
		Updates: models.RequestUpdateFields{GroupsAdd: []string{"g"}}}); err == nil || err.Error() != pkgerrors.ErrUserNotFound {
		t.Fatalf("unknown user err = %v, want %q", err, pkgerrors.ErrUserNotFound)
	}
	if err := s.RequestUpdate(ctx, "root-r", &models.RequestUpdateRequest{
		Updates: models.RequestUpdateFields{GroupsAdd: []string{"g"}}}); err == nil || err.Error() != pkgerrors.ErrUnauthorized {
		t.Fatalf("superuser err = %v, want %q", err, pkgerrors.ErrUnauthorized)
	}
	if err := s.RequestUpdate(ctx, "req-1", &models.RequestUpdateRequest{}); err == nil ||
		err.Error() != pkgerrors.ErrInvalidRequest {
		t.Fatalf("empty err = %v, want %q", err, pkgerrors.ErrInvalidRequest)
	}
	// Permissions/groups catalogues are not loaded in unit tests.
	if err := s.RequestUpdate(ctx, "req-1", &models.RequestUpdateRequest{
		Updates: models.RequestUpdateFields{PermissionsAdd: []string{"read"}}}); err == nil || err.Error() != pkgerrors.ErrPermissionsNotLoaded {
		t.Fatalf("permissions err = %v, want %q", err, pkgerrors.ErrPermissionsNotLoaded)
	}
	if err := s.RequestUpdate(ctx, "req-1", &models.RequestUpdateRequest{
		Updates: models.RequestUpdateFields{GroupsAdd: []string{"g"}}}); err == nil || err.Error() != pkgerrors.ErrGroupsNotLoaded {
		t.Fatalf("groups err = %v, want %q", err, pkgerrors.ErrGroupsNotLoaded)
	}
}
