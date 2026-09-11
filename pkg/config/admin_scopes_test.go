package config

import "testing"

const scopedAdmin = "helpdesk@example.com"

func TestAdminScopesUnsetLeavesAdminsUnrestricted(t *testing.T) {
	withSecrets(t, map[string]string{})

	scopes, enforced := AdminScopesFor(scopedAdmin)
	if enforced {
		t.Fatal("AdminScopesFor enforced with no ADMIN_SCOPES_JSON — admins must keep the access they had before scopes existed")
	}
	if len(scopes) != 0 {
		t.Fatalf("scopes = %v, want none", scopes)
	}
}

func TestAdminScopesListedAdminIsRestrictedToTheirEntry(t *testing.T) {
	withSecrets(t, map[string]string{
		"admin_scopes_json": `{"helpdesk@example.com":["garde:users:read","garde:users:write"]}`,
	})

	scopes, enforced := AdminScopesFor(scopedAdmin)
	if !enforced {
		t.Fatal("AdminScopesFor did not enforce for a listed admin")
	}
	if len(scopes) != 2 || scopes[0] != ScopeAdminUsersRead || scopes[1] != ScopeAdminUsersWrite {
		t.Fatalf("scopes = %v, want read and write", scopes)
	}
}

// Restricting is opt-in per admin, so introducing the secret must not lock
// out the admins nobody has got round to listing.
func TestAdminScopesUnlistedAdminStaysUnrestricted(t *testing.T) {
	withSecrets(t, map[string]string{
		"admin_scopes_json": `{"helpdesk@example.com":["garde:users:read"]}`,
	})

	if _, enforced := AdminScopesFor("someone-else@example.com"); enforced {
		t.Fatal("AdminScopesFor enforced for an admin with no entry")
	}
}

// An empty list is a restriction, not an absence.
func TestAdminScopesEmptyListDeniesEverything(t *testing.T) {
	withSecrets(t, map[string]string{
		"admin_scopes_json": `{"helpdesk@example.com":[]}`,
	})

	scopes, enforced := AdminScopesFor(scopedAdmin)
	if !enforced {
		t.Fatal("an explicit empty list must enforce, otherwise it silently grants everything")
	}
	if len(scopes) != 0 {
		t.Fatalf("scopes = %v, want none", scopes)
	}
}

// Startup validation rejects bad JSON, so this branch is only reachable by a
// hot reload of a broken secret. Denying is the safe answer; quietly handing
// every admin their full bundle back is not.
func TestAdminScopesMalformedSecretFailsClosed(t *testing.T) {
	withSecrets(t, map[string]string{
		"admin_scopes_json": `{"helpdesk@example.com": "not-a-list"`,
	})

	scopes, enforced := AdminScopesFor(scopedAdmin)
	if !enforced {
		t.Fatal("malformed ADMIN_SCOPES_JSON must not read as no restriction")
	}
	if len(scopes) != 0 {
		t.Fatalf("scopes = %v, want none", scopes)
	}
}

func TestIsKnownAdminScope(t *testing.T) {
	for _, scope := range AllAdminScopes() {
		if !IsKnownAdminScope(scope) {
			t.Fatalf("IsKnownAdminScope(%q) = false for a scope in AllAdminScopes", scope)
		}
	}

	for _, scope := range []string{"", "users:read", "garde:users:readd", "garde:*", "admin"} {
		if IsKnownAdminScope(scope) {
			t.Fatalf("IsKnownAdminScope(%q) = true, want false", scope)
		}
	}
}
