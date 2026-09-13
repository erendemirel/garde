package repository

import (
	"context"
	"testing"
)

// SQLite CRUD against an isolated temp DATA_DIR. Exercises the schema,
// uniqueness, visibility mappings and cascade deletes without touching the
// checked-in data/permissions.db.
func newIsolatedPermRepo(t *testing.T) *PermissionRepository {
	t.Helper()
	t.Setenv("DATA_DIR", t.TempDir())
	repo, err := NewPermissionRepository()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func TestPermissionCRUD(t *testing.T) {
	ctx := context.Background()
	r := newIsolatedPermRepo(t)

	perm, err := r.CreatePermission(ctx, "read_users", "read users")
	if err != nil {
		t.Fatal(err)
	}
	if perm.Name != "read_users" {
		t.Fatalf("name = %q", perm.Name)
	}
	if _, err := r.CreatePermission(ctx, "read_users", "dup"); err == nil {
		t.Fatal("duplicate permission name accepted")
	}

	got, err := r.GetPermissionByName(ctx, "read_users")
	if err != nil || got.Definition != "read users" {
		t.Fatalf("get by name = %+v, %v", got, err)
	}
	if _, err := r.GetPermissionByName(ctx, "missing"); err == nil {
		t.Fatal("missing permission returns nil error")
	}
	byID, err := r.GetPermissionByID(ctx, perm.ID)
	if err != nil || byID.Name != "read_users" {
		t.Fatalf("get by id = %+v, %v", byID, err)
	}

	if err := r.UpdatePermission(ctx, perm.ID, "updated"); err != nil {
		t.Fatal(err)
	}
	updated, err := r.GetPermissionByName(ctx, "read_users")
	if err != nil || updated.Definition != "updated" {
		t.Fatalf("after update = %+v, %v", updated, err)
	}

	all, err := r.GetAllPermissions(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("all = %v, %v", all, err)
	}

	if err := r.DeletePermission(ctx, perm.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetPermissionByName(ctx, "read_users"); err == nil {
		t.Fatal("deleted permission still readable")
	}
}

func TestGroupCRUD(t *testing.T) {
	ctx := context.Background()
	r := newIsolatedPermRepo(t)

	group, err := r.CreateGroup(ctx, "eng", "engineering")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.CreateGroup(ctx, "eng", "dup"); err == nil {
		t.Fatal("duplicate group name accepted")
	}
	got, err := r.GetGroupByName(ctx, "eng")
	if err != nil || got.Definition != "engineering" {
		t.Fatalf("get by name = %+v, %v", got, err)
	}
	if err := r.UpdateGroup(ctx, group.ID, "eng2"); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteGroup(ctx, group.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetGroupByName(ctx, "eng"); err == nil {
		t.Fatal("deleted group still readable")
	}
}

func TestPermissionVisibilityAndCascade(t *testing.T) {
	ctx := context.Background()
	r := newIsolatedPermRepo(t)

	perm, err := r.CreatePermission(ctx, "deploy", "deploy apps")
	if err != nil {
		t.Fatal(err)
	}
	group, err := r.CreateGroup(ctx, "ops", "operators")
	if err != nil {
		t.Fatal(err)
	}

	visible, err := r.IsPermissionVisibleToGroups(ctx, "deploy", []string{"ops"})
	if err != nil || visible {
		t.Fatalf("visible before mapping = %v, %v", visible, err)
	}
	if got, err := r.GetVisiblePermissions(ctx, nil); err != nil || len(got) != 0 {
		t.Fatalf("empty groups = %v, %v", got, err)
	}

	if err := r.AddPermissionVisibility(ctx, perm.ID, group.ID); err != nil {
		t.Fatal(err)
	}
	visible, err = r.IsPermissionVisibleToGroups(ctx, "deploy", []string{"ops"})
	if err != nil || !visible {
		t.Fatalf("visible after mapping = %v, %v", visible, err)
	}
	visible, err = r.IsPermissionVisibleToGroups(ctx, "deploy", []string{"other"})
	if err != nil || visible {
		t.Fatalf("visible to unrelated group = %v, %v", visible, err)
	}
	listed, err := r.GetVisiblePermissions(ctx, []string{"ops"})
	if err != nil || len(listed) != 1 || listed[0].Name != "deploy" {
		t.Fatalf("visible list = %v, %v", listed, err)
	}

	if err := r.RemovePermissionVisibility(ctx, perm.ID, group.ID); err != nil {
		t.Fatal(err)
	}
	if visible, _ := r.IsPermissionVisibleToGroups(ctx, "deploy", []string{"ops"}); visible {
		t.Fatal("still visible after removal")
	}

	// Re-add, then delete the group: the mapping must cascade away.
	if err := r.AddPermissionVisibility(ctx, perm.ID, group.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteGroup(ctx, group.ID); err != nil {
		t.Fatal(err)
	}
	groups, err := r.GetGroupsForPermission(ctx, "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 0 {
		t.Fatalf("cascade left %d mappings", len(groups))
	}
}
