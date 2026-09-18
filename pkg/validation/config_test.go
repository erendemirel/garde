package validation

import (
	"os"
	"path/filepath"
	"testing"

	"garde/pkg/config"
)

// Secrets arrive as one file per key, so a fixture is a directory.
func withSecrets(t *testing.T, values map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, value := range values {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatalf("writing secret %s: %v", name, err)
		}
	}
	if err := config.Init(dir); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
}

const (
	testSuperuser  = "root@example.com"
	testAdminUsers = `{"helpdesk@example.com":"DevAdminTest123!"}`
)

// Both likely mistakes — an address that names nobody and a mistyped scope —
// fail silently at runtime by leaving the admin unrestricted. Startup is the
// only place they are visible, so each one must stop the process.
func TestValidateAdminScopes(t *testing.T) {
	cases := []struct {
		name      string
		scopes    string
		wantError bool
	}{
		{
			name:      "unset is allowed",
			scopes:    "",
			wantError: false,
		},
		{
			name:      "a known scope for a real admin",
			scopes:    `{"helpdesk@example.com":["garde:users:read","garde:users:write"]}`,
			wantError: false,
		},
		{
			name:      "an explicit empty list is a valid restriction",
			scopes:    `{"helpdesk@example.com":[]}`,
			wantError: false,
		},
		{
			name:      "a mistyped scope stops startup",
			scopes:    `{"helpdesk@example.com":["garde:users:reed"]}`,
			wantError: true,
		},
		{
			name:      "an unprefixed scope stops startup",
			scopes:    `{"helpdesk@example.com":["users:read"]}`,
			wantError: true,
		},
		{
			// The dangerous typo: restricts nobody, and the real admin keeps
			// their full bundle.
			name:      "an address absent from ADMIN_USERS_JSON stops startup",
			scopes:    `{"helpdsek@example.com":["garde:users:read"]}`,
			wantError: true,
		},
		{
			name:      "the superuser cannot be restricted",
			scopes:    `{"root@example.com":["garde:users:read"]}`,
			wantError: true,
		},
		{
			name:      "a malformed secret stops startup",
			scopes:    `{"helpdesk@example.com":"garde:users:read"}`,
			wantError: true,
		},
		{
			name:      "an unparseable email stops startup",
			scopes:    `{"not-an-email":["garde:users:read"]}`,
			wantError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withSecrets(t, map[string]string{
				"superuser_email":   testSuperuser,
				"admin_users_json":  testAdminUsers,
				"admin_scopes_json": tc.scopes,
			})

			err := validateAdminScopes()
			if tc.wantError && err == nil {
				t.Fatal("validateAdminScopes() = nil, want an error")
			}
			if !tc.wantError && err != nil {
				t.Fatalf("validateAdminScopes() = %v, want nil", err)
			}
		})
	}
}

// Every scope an operator may configure has to be one a route actually
// declares, otherwise the vocabulary promises enforcement it does not have.
func TestEveryAdminScopeIsAccepted(t *testing.T) {
	for _, scope := range config.AllAdminScopes() {
		if !config.IsKnownAdminScope(scope) {
			t.Fatalf("IsKnownAdminScope(%q) = false", scope)
		}
	}
}
