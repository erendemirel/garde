package service

import (
	"testing"

	"garde/internal/models"
)

// Pure catalogue helpers with permRepo forced nil: everything resolves to the
// documented fallbacks rather than touching the permission store.
func TestNilRepoHelpers(t *testing.T) {
	prev := permRepo
	permRepo = nil
	t.Cleanup(func() { permRepo = prev })

	groups := models.UserGroups{"eng": true, "ops": false}
	names := GetUserGroupNames(groups)
	if len(names) != 1 || names[0] != "eng" {
		t.Fatalf("names = %v", names)
	}
	if IsValidPermission("read") {
		t.Fatal("permission valid without catalogue")
	}
	if IsValidUserGroup("eng") {
		t.Fatal("group valid without catalogue")
	}
	if len(GetVisiblePermissions([]string{"eng"})) != 0 {
		t.Fatal("visible permissions without catalogue")
	}
	if IsPermissionVisibleToGroups("read", []string{"eng"}) {
		t.Fatal("visibility without catalogue")
	}
	if got := GetPermissionInfo("read"); got.Name != "read" || got.Description == "" {
		t.Fatalf("perm info = %+v", got)
	}
	if got := GetGroupInfo("eng"); got.Name != "eng" || got.Description == "" {
		t.Fatalf("group info = %+v", got)
	}
}

func TestFilterPendingUpdatesForAdmin(t *testing.T) {
	if filterPendingUpdatesForAdmin(nil, models.UserGroups{"eng": true}) != nil {
		t.Fatal("nil pending must stay nil")
	}
	adminGroups := models.UserGroups{"eng": true}
	pending := &models.UserUpdateRequest{Fields: models.UserUpdateFields{
		PermissionsAdd:    []models.Permission{"read"},
		PermissionsRemove: []models.Permission{"write"},
		GroupsAdd:         []models.UserGroup{"eng", "ops"},
		GroupsRemove:      []models.UserGroup{"old"},
	}}
	got := filterPendingUpdatesForAdmin(pending, adminGroups)
	if got == nil {
		t.Fatal("expected surviving removes")
	}
	// Without a catalogue no permission-add is visible, so adds drop; the
	// remove lists always survive the shared-group gate.
	if len(got.Fields.PermissionsAdd) != 0 {
		t.Fatalf("perm adds = %v, want dropped without catalogue", got.Fields.PermissionsAdd)
	}
	if len(got.Fields.PermissionsRemove) != 1 {
		t.Fatalf("perm removes = %v", got.Fields.PermissionsRemove)
	}
	if len(got.Fields.GroupsAdd) != 1 || got.Fields.GroupsAdd[0] != "eng" {
		t.Fatalf("group adds = %v, want only eng", got.Fields.GroupsAdd)
	}
	if len(got.Fields.GroupsRemove) != 1 {
		t.Fatalf("group removes = %v", got.Fields.GroupsRemove)
	}

	// Everything filtered away collapses to nil (caller shows "nothing to review").
	empty := &models.UserUpdateRequest{Fields: models.UserUpdateFields{
		PermissionsAdd: []models.Permission{"read"},
	}}
	if filterPendingUpdatesForAdmin(empty, models.UserGroups{}) != nil {
		t.Fatal("fully filtered request must collapse to nil")
	}
}
