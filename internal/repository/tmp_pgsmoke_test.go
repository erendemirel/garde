package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"garde/internal/models"
)

func newSmokeStore(t *testing.T) *Store {
	t.Helper()
	return newDurableStore(t)
}

func TestSmokeUserLifecycle(t *testing.T) {
	initTestConfig(t, map[string]string{"mfa_encryption_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="})
	ctx := context.Background()
	s := newSmokeStore(t)

	now := time.Now()
	u := &models.User{
		ID:           "u-1",
		Email:        "A@Example.com ",
		PasswordHash: "HASH",
		MFASecret:    "JBSWY3DPEHPK3PXP",
		Status:       models.UserStatusOk,
		CreatedAt:    now,
		UpdatedAt:    now,
		Permissions:  models.UserPermissions{"read": true},
		Groups:       models.UserGroups{"eng": true},
		PendingUpdates: &models.UserUpdateRequest{
			RequestedAt: now,
			Fields:      models.UserUpdateFields{PermissionsAdd: []models.Permission{"write"}},
		},
	}
	if err := s.StoreUser(ctx, u); err != nil {
		t.Fatalf("StoreUser: %v", err)
	}

	byEmail, err := s.GetUserByEmail(ctx, "a@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if byEmail.ID != "u-1" || byEmail.PasswordHash != "HASH" || byEmail.MFASecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("round trip = %+v", byEmail)
	}
	if !byEmail.Permissions["read"] || !byEmail.Groups["eng"] {
		t.Fatalf("json columns = %+v %+v", byEmail.Permissions, byEmail.Groups)
	}
	if byEmail.PendingUpdates == nil || len(byEmail.PendingUpdates.Fields.PermissionsAdd) != 1 {
		t.Fatalf("pending = %+v", byEmail.PendingUpdates)
	}
	if !byEmail.LastLogin.IsZero() {
		t.Fatalf("last login = %v, want zero", byEmail.LastLogin)
	}

	// Duplicate email on create.
	dup := &models.User{ID: "u-2", Email: "a@example.com", Status: models.UserStatusOk}
	if err := s.StoreUser(ctx, dup); !errors.Is(err, ErrEmailAlreadyExists) {
		t.Fatalf("duplicate = %v, want ErrEmailAlreadyExists", err)
	}

	// Optimistic concurrency.
	fresh, err := s.GetUserByID(ctx, "u-1")
	if err != nil {
		t.Fatal(err)
	}
	stale := *fresh
	fresh.Status = models.UserStatusLockedByAdmin
	fresh.UpdatedAt = time.Now().Add(time.Second)
	if err := s.StoreUser(ctx, fresh); err != nil {
		t.Fatalf("fresh write: %v", err)
	}
	stale.Status = models.UserStatusLockedBySecurity
	if err := s.StoreUser(ctx, &stale); !errors.Is(err, ErrConcurrentUpdate) {
		t.Fatalf("stale write = %v, want ErrConcurrentUpdate", err)
	}
	winner, _ := s.GetUserByID(ctx, "u-1")
	if winner.Status != models.UserStatusLockedByAdmin {
		t.Fatalf("loser overwrote winner: %q", winner.Status)
	}

	// Empty password hash must not blank the stored one.
	winner.PasswordHash = ""
	winner.UpdatedAt = time.Now()
	if err := s.StoreUser(ctx, winner); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUserByID(ctx, "u-1"); got.PasswordHash != "HASH" {
		t.Fatalf("password hash = %q, want preserved", got.PasswordHash)
	}

	// Clearing the MFA secret requires ClearUserMFASecret — empty MFASecret on
	// StoreUser is preserved so partial updates cannot wipe enrollment.
	cleared, _ := s.GetUserByID(ctx, "u-1")
	cleared.PendingUpdates = nil
	cleared.UpdatedAt = time.Now()
	if err := s.StoreUser(ctx, cleared); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearUserMFASecret(ctx, "u-1"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUserByID(ctx, "u-1")
	if got.MFASecret != "" || got.PendingUpdates != nil {
		t.Fatalf("clear = %+v", got)
	}

	// Email change frees the old address.
	got.Email = "new@example.com"
	got.UpdatedAt = time.Now()
	if err := s.StoreUser(ctx, got); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUserByEmail(ctx, "a@example.com"); err == nil {
		t.Fatal("stale email still resolves")
	}

	locked, err := s.GetLockedUsers(ctx)
	if err != nil || len(locked) != 1 {
		t.Fatalf("locked = %d, %v", len(locked), err)
	}
	all, err := s.GetAllUsers(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("all = %d, %v", len(all), err)
	}

	if err := s.DeleteUser(ctx, "u-1"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := s.GetUserByID(ctx, "u-1"); err == nil {
		t.Fatal("deleted user still readable")
	}
}

func TestSmokePATLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newSmokeStore(t)

	owner := &models.User{ID: "u-pat", Email: "pat@example.com", Status: models.UserStatusOk}
	if err := s.StoreUser(ctx, owner); err != nil {
		t.Fatal(err)
	}

	token := &models.PersonalAccessToken{
		ID: "pat-1", UserID: "u-pat", Name: "ci", SecretHash: "hash", CreatedAt: time.Now().UTC(),
	}
	if err := s.StorePAT(ctx, token); err != nil {
		t.Fatalf("StorePAT: %v", err)
	}
	if err := s.TouchPAT(ctx, "pat-1"); err != nil {
		t.Fatalf("TouchPAT: %v", err)
	}
	got, err := s.GetPAT(ctx, "pat-1")
	if err != nil || got.LastUsedAt == nil {
		t.Fatalf("GetPAT = %+v, %v", got, err)
	}
	if n, err := s.CountPATsByUser(ctx, "u-pat"); err != nil || n != 1 {
		t.Fatalf("count = %d, %v", n, err)
	}

	if _, err := s.RevokePAT(ctx, "pat-1", "someone-else"); !errors.Is(err, ErrPATNotFound) {
		t.Fatalf("cross-user revoke = %v, want ErrPATNotFound", err)
	}
	revoked, err := s.RevokePAT(ctx, "pat-1", "u-pat")
	if err != nil || revoked.RevokedAt == nil {
		t.Fatalf("revoke = %+v, %v", revoked, err)
	}
	// Idempotent.
	if again, err := s.RevokePAT(ctx, "pat-1", "u-pat"); err != nil || again.RevokedAt == nil {
		t.Fatalf("second revoke = %+v, %v", again, err)
	}
	// Revoked record kept, but excluded from the active listing and the cap.
	if _, err := s.GetPAT(ctx, "pat-1"); err != nil {
		t.Fatalf("revoked record gone: %v", err)
	}
	list, err := s.ListPATsByUser(ctx, "u-pat")
	if err != nil || len(list) != 0 {
		t.Fatalf("list = %d, %v", len(list), err)
	}
	if n, _ := s.CountPATsByUser(ctx, "u-pat"); n != 0 {
		t.Fatalf("count after revoke = %d", n)
	}
	if _, err := s.GetPAT(ctx, "missing"); !errors.Is(err, ErrPATNotFound) {
		t.Fatalf("missing = %v", err)
	}

	// Deleting the owner cascades.
	if err := s.DeleteUser(ctx, "u-pat"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPAT(ctx, "pat-1"); !errors.Is(err, ErrPATNotFound) {
		t.Fatalf("cascade = %v, want ErrPATNotFound", err)
	}
}

func TestSmokeAPIKeyLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newSmokeStore(t)

	mk := func(id, tenant string, created time.Time) *models.ServiceAPIKey {
		return &models.ServiceAPIKey{
			ID: id, TenantID: tenant, Name: id, SecretHash: "h-" + id,
			Scopes: []string{models.ScopeValidate}, CreatedAt: created,
		}
	}
	base := time.Now().UTC()
	for i, key := range []*models.ServiceAPIKey{
		mk("k-1", "acme", base.Add(-2*time.Hour)),
		mk("k-2", "acme", base.Add(-time.Hour)),
		mk("k-3", "other", base),
	} {
		if err := s.StoreServiceAPIKey(ctx, key); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}

	got, err := s.GetServiceAPIKey(ctx, "k-1")
	if err != nil || len(got.Scopes) != 1 || got.Scopes[0] != models.ScopeValidate {
		t.Fatalf("get = %+v, %v", got, err)
	}
	if _, err := s.GetServiceAPIKey(ctx, "nope"); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("missing = %v, want ErrAPIKeyNotFound", err)
	}

	all, err := s.ListServiceAPIKeys(ctx)
	if err != nil || len(all) != 3 || all[0].ID != "k-3" {
		t.Fatalf("list = %+v, %v", all, err)
	}
	acme, err := s.ListServiceAPIKeysByTenant(ctx, "acme")
	if err != nil || len(acme) != 2 {
		t.Fatalf("tenant list = %d, %v", len(acme), err)
	}

	if err := s.TouchServiceAPIKey(ctx, "k-1"); err != nil {
		t.Fatal(err)
	}
	if touched, _ := s.GetServiceAPIKey(ctx, "k-1"); touched.LastUsedAt == nil || touched.Name != "k-1" {
		t.Fatalf("touch rewrote record: %+v", touched)
	}

	revoked, err := s.RevokeServiceAPIKeysByTenant(ctx, "acme")
	if err != nil || len(revoked) != 2 {
		t.Fatalf("tenant revoke = %d, %v", len(revoked), err)
	}
	// Idempotent, and the record survives.
	again, err := s.RevokeServiceAPIKey(ctx, "k-1")
	if err != nil || again.RevokedAt == nil {
		t.Fatalf("second revoke = %+v, %v", again, err)
	}
	if left, _ := s.ListServiceAPIKeys(ctx); len(left) != 3 {
		t.Fatalf("revoke dropped records: %d", len(left))
	}

	if err := s.DeleteServiceAPIKey(ctx, "k-3"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetServiceAPIKey(ctx, "k-3"); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("after delete = %v", err)
	}
}

func TestSmokePermissionCatalogue(t *testing.T) {
	ctx := context.Background()
	repo, err := NewPermissionRepository(newTestDB(t))
	if err != nil {
		t.Fatal(err)
	}

	perm, err := repo.CreatePermission(ctx, "read_users", "read users")
	if err != nil || perm.ID == 0 {
		t.Fatalf("create = %+v, %v", perm, err)
	}
	if _, err := repo.CreatePermission(ctx, "read_users", "dup"); err == nil {
		t.Fatal("duplicate accepted")
	}
	group, err := repo.CreateGroup(ctx, "eng", "engineering")
	if err != nil || group.ID == 0 {
		t.Fatalf("create group = %+v, %v", group, err)
	}
	if err := repo.AddPermissionVisibility(ctx, perm.ID, group.ID); err != nil {
		t.Fatal(err)
	}

	visible, err := repo.GetVisiblePermissions(ctx, []string{"eng", "ops"})
	if err != nil || len(visible) != 1 {
		t.Fatalf("visible = %+v, %v", visible, err)
	}
	ok, err := repo.IsPermissionVisibleToGroups(ctx, "read_users", []string{"ops", "eng"})
	if err != nil || !ok {
		t.Fatalf("visible to groups = %v, %v", ok, err)
	}
	groups, err := repo.GetGroupsForPermission(ctx, "read_users")
	if err != nil || len(groups) != 1 {
		t.Fatalf("groups for permission = %+v, %v", groups, err)
	}
	vis, err := repo.GetAllPermissionVisibility(ctx)
	if err != nil || len(vis["read_users"]) != 1 {
		t.Fatalf("visibility map = %+v, %v", vis, err)
	}

	if err := repo.UpdatePermission(ctx, perm.ID, "updated"); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.GetPermissionByID(ctx, perm.ID); got.Definition != "updated" {
		t.Fatalf("update = %+v", got)
	}
	if err := repo.RemovePermissionVisibility(ctx, perm.ID, group.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeletePermission(ctx, perm.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteGroup(ctx, group.ID); err != nil {
		t.Fatal(err)
	}
	if all, _ := repo.GetAllPermissions(ctx); len(all) != 0 {
		t.Fatalf("remaining = %+v", all)
	}
}

func TestSmokeMigrateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("schema_migrations rows = %d, want 2", count)
	}
}
