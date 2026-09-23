package models

import "time"

// Scopes an issued key can carry. Stored as a list so adding a scope later
// does not change the shape of records already in Postgres.
const (
	ScopeValidate = "validate"
	// ScopeAuth skips Cap on public auth POSTs (login, register, password
	// reset) when Cap is enabled. Validate-only keys do not get this.
	ScopeAuth = "auth"
)

// Audience binds a key to one /validate surface. It is set at issue time and
// enforced by the listener that mounts the route — not by the key string.
const (
	AudienceInternal = "internal" // private service listener (mesh + mTLS)
	AudienceTenant   = "tenant"   // public /validate when published
)

// APIKeyScopeInfo is the operator-facing description of one grantable scope.
// The UI sources this list from the server so adding a scope does not need a
// frontend release, and so the UI cannot offer a name the server rejects.
type APIKeyScopeInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// APIKeyAudienceInfo describes one grantable audience for the admin UI.
type APIKeyAudienceInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func IsKnownAPIKeyScope(scope string) bool {
	return scope == ScopeValidate || scope == ScopeAuth
}

func IsKnownAPIKeyAudience(audience string) bool {
	return audience == AudienceInternal || audience == AudienceTenant
}

// AllAPIKeyScopes is the closed vocabulary CreateAPIKey accepts. Keep this and
// IsKnownAPIKeyScope in lockstep: every name listed here must pass the check,
// and every name the check accepts must appear here.
func AllAPIKeyScopes() []APIKeyScopeInfo {
	return []APIKeyScopeInfo{
		{
			Name:        ScopeValidate,
			Description: "Call /validate to check whether a session is still valid",
		},
		{
			Name:        ScopeAuth,
			Description: "Call enabled public auth routes (login, and register/password/email-verify when public self-service is on) without Cap when Cap is enabled",
		},
	}
}

// AllAPIKeyAudiences is the closed vocabulary CreateAPIKey accepts for audience.
func AllAPIKeyAudiences() []APIKeyAudienceInfo {
	return []APIKeyAudienceInfo{
		{
			Name:        AudienceInternal,
			Description: "Private service listener only (mesh; mTLS when configured)",
		},
		{
			Name:        AudienceTenant,
			Description: "Public /validate only (when public_validate is enabled)",
		},
	}
}

// ServiceAPIKey is a credential issued to a single external tenant or
// internal service, for calling /validate.
//
// The plaintext key is returned once, at creation. Only SecretHash is stored,
// so a key the caller has lost is replaced rather than recovered.
// Bounds on issued lifetime. A credential that never expires is a credential
// nobody ever rotates, so expiry is the default and opting out has to be
// deliberate. The ceiling exists so "expires_in" cannot be used to reach the
// same place by asking for a century.
const (
	DefaultAPIKeyTTL = 90 * 24 * time.Hour
	MaxAPIKeyTTL     = 365 * 24 * time.Hour
)

type ServiceAPIKey struct {
	ID string `json:"id"`
	// TenantID names the holder rather than the key. Several keys share one,
	// which is what makes deliberate rotation and "revoke everything this
	// caller has" possible — the questions that matter during an incident.
	TenantID string `json:"tenant_id"`
	// Audience is which /validate surface may accept this key. Empty means a
	// pre-audience record: still usable on any surface until re-issued.
	Audience   string     `json:"audience,omitempty"`
	Name       string     `json:"name"`
	SecretHash string     `json:"secret_hash"`
	Scopes     []string   `json:"scopes"`
	RateLimit  int        `json:"rate_limit,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

func (k *ServiceAPIKey) Revoked() bool { return k.RevokedAt != nil }

func (k *ServiceAPIKey) Expired(now time.Time) bool {
	return k.ExpiresAt != nil && now.After(*k.ExpiresAt)
}

func (k *ServiceAPIKey) Usable(now time.Time) bool {
	return !k.Revoked() && !k.Expired(now)
}

func (k *ServiceAPIKey) HasScope(scope string) bool {
	for _, s := range k.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// MatchesAudience reports whether this key may be used on a mount that
// requires the given audience. An empty required value means the mount does
// not restrict by audience (single-listener). An empty key audience is a
// pre-audience record and is accepted on every surface until re-issued.
func (k *ServiceAPIKey) MatchesAudience(required string) bool {
	if required == "" {
		return true
	}
	if k.Audience == "" {
		return true
	}
	return k.Audience == required
}

type CreateAPIKeyRequest struct {
	// TenantID identifies the external party that will hold the key. Required,
	// so that every credential can be traced back to a holder and revoked with
	// its siblings.
	//
	// None of these carry binding:"required". The handler validates them and
	// answers with a message naming the field; a binding failure would
	// collapse all of that into one generic "invalid request".
	TenantID string `json:"tenant_id"`
	// Audience is which /validate surface may accept the key: internal or
	// tenant. Required for new issues.
	Audience string `json:"audience"`
	Name     string `json:"name"`
	// Scopes must be listed explicitly. Defaulting them would grant more than
	// was asked for, which is the wrong direction for a credential.
	Scopes []string `json:"scopes"`
	// ExpiresIn is a Go duration such as "2160h". Omitted means
	// DefaultAPIKeyTTL; it may not exceed MaxAPIKeyTTL.
	ExpiresIn string `json:"expires_in,omitempty"`
	// NeverExpires opts out of expiry altogether. It is a separate flag
	// rather than an empty ExpiresIn so that an immortal credential can only
	// be issued on purpose.
	NeverExpires bool `json:"never_expires,omitempty"`
	// RateLimit overrides the authenticated tier for this caller, in requests
	// per rate-limit window. Zero means use the tier default.
	RateLimit int `json:"rate_limit,omitempty"`
}

// APIKeyResponse is the safe view of a key: everything except the secret.
type APIKeyResponse struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Audience   string     `json:"audience,omitempty"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	RateLimit  int        `json:"rate_limit,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// CreateAPIKeyResponse is the only response that ever carries the plaintext
// key. It cannot be retrieved again afterwards.
type CreateAPIKeyResponse struct {
	APIKeyResponse
	Key string `json:"key"`
}

type ListAPIKeysResponse struct {
	Keys  []APIKeyResponse `json:"keys"`
	Total int              `json:"total"`
}

// RevokeTenantKeysResponse reports what a revoke-by-tenant call took out, so
// the operator can see the blast radius of what they just did.
type RevokeTenantKeysResponse struct {
	TenantID string           `json:"tenant_id"`
	Keys     []APIKeyResponse `json:"keys"`
	Revoked  int              `json:"revoked"`
}

func NewAPIKeyResponse(k *ServiceAPIKey) APIKeyResponse {
	scopes := k.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	return APIKeyResponse{
		ID:         k.ID,
		TenantID:   k.TenantID,
		Audience:   k.Audience,
		Name:       k.Name,
		Scopes:     scopes,
		RateLimit:  k.RateLimit,
		CreatedAt:  k.CreatedAt,
		CreatedBy:  k.CreatedBy,
		ExpiresAt:  k.ExpiresAt,
		RevokedAt:  k.RevokedAt,
		LastUsedAt: k.LastUsedAt,
	}
}
