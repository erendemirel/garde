package config

import (
	"encoding/json"
	"log/slog"
	"strings"
)

// Admin scopes narrow what a single admin may do on the admin routes.
//
// Without them "admin" is one bundle: whoever may update a user may also
// delete them and revoke their sessions. A scope names one of those
// operations, so a helpdesk admin can be given reading and updating without
// deletion.
//
// The names carry a "garde:" prefix for a reason. Users already hold a
// Permissions list, which garde stores on behalf of other applications and
// never acts on. These are the opposite: garde enforces them, in middleware,
// before the handler runs. The prefix keeps the enforced set visibly distinct
// from the custodied one on a principal that holds both. Per-tenant API key
// scopes need no prefix because keys carry no permissions to be confused
// with.
//
// The vocabulary is compiled in rather than stored, so that "this scope
// exists" and "this scope is enforced" stay the same fact: a name here does
// nothing until some route declares it via middleware.RequireAdminScope.
//
// They live in pkg/config because configuration is where they come from —
// unlike API key scopes, which are data in Redis.
const (
	ScopeAdminUsersRead      = "garde:users:read"
	ScopeAdminUsersWrite     = "garde:users:write"
	ScopeAdminUsersDelete    = "garde:users:delete"
	ScopeAdminSessionsRevoke = "garde:sessions:revoke"
)

// AllAdminScopes lists the vocabulary, for operator-facing error messages.
func AllAdminScopes() []string {
	return []string{
		ScopeAdminUsersRead,
		ScopeAdminUsersWrite,
		ScopeAdminUsersDelete,
		ScopeAdminSessionsRevoke,
	}
}

func IsKnownAdminScope(scope string) bool {
	switch scope {
	case ScopeAdminUsersRead, ScopeAdminUsersWrite, ScopeAdminUsersDelete, ScopeAdminSessionsRevoke:
		return true
	default:
		return false
	}
}

// ADMIN_SCOPES_JSON narrows individual admins, e.g.
//
//	{"helpdesk@example.com":["garde:users:read","garde:users:write"]}
//
// It sits in the secrets directory next to ADMIN_USERS_JSON, so it is
// provisioned by an operator through Vault rather than through the admin API.
// That placement is deliberate: UpdateUser has no self-target guard and
// admins may edit users who share a group with them, so an admin's own
// authorization data must not live in a record an admin can write. Keeping it
// out of Redis keeps "no admin can grant themselves more admin" true.
const AdminScopesKey = "ADMIN_SCOPES_JSON"

// adminScopes reports the parsed map, whether the secret was set at all, and
// whether it parsed.
func adminScopes() (m map[string][]string, configured, ok bool) {
	raw := strings.TrimSpace(Get(AdminScopesKey))
	if raw == "" {
		return nil, false, true
	}

	parsed := map[string][]string{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		slog.Error("Config: ADMIN_SCOPES_JSON is not valid JSON; denying every scoped admin route until it is fixed", "error", err)
		return nil, true, false
	}
	return parsed, true, true
}

// GetAdminScopesMap exposes the configured restrictions. It is nil when the
// secret is unset or unparseable; callers that must tell those apart should
// use AdminScopesFor.
func GetAdminScopesMap() map[string][]string {
	m, _, ok := adminScopes()
	if !ok {
		return nil
	}
	return m
}

// AdminScopesFor resolves one admin's scopes.
//
// enforced is false when no restriction applies, and the caller should then
// treat the admin as holding everything — which is what an admin held before
// scopes existed. Listing an admin is therefore opt-in: adding the secret
// does not lock out admins who have no entry yet. The cost is that a
// misspelled email leaves the real admin unrestricted, which is why
// ValidateConfig refuses to start on an entry naming nobody.
//
// An explicit empty list is a restriction, not an absence: it denies every
// scoped route.
//
// A malformed secret is the one case that fails closed. Startup validation
// rejects bad JSON, so the only way to reach that branch is a hot reload of a
// broken secret, and there the safe answer is to deny rather than quietly
// hand every admin back their full bundle.
func AdminScopesFor(email string) (scopes []string, enforced bool) {
	m, configured, ok := adminScopes()
	if !configured {
		return nil, false
	}
	if !ok {
		return nil, true
	}

	scopes, listed := m[email]
	if !listed {
		return nil, false
	}
	return scopes, true
}
