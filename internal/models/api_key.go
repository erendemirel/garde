package models

import "time"

// Scopes an issued key can carry. Only session validation exists today; the
// stored field is a list so that adding a second scope later does not change
// the shape of records already in Redis.
const ScopeValidate = "validate"

// APIKeyScopeInfo is the operator-facing description of one grantable scope.
// The UI sources this list from the server so adding a scope does not need a
// frontend release, and so the UI cannot offer a name the server rejects.
type APIKeyScopeInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func IsKnownAPIKeyScope(scope string) bool {
	return scope == ScopeValidate
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
	}
}

// ServiceAPIKey is a credential issued to a single calling service or tenant,
// as opposed to the one shared API_KEY that comes from configuration.
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
	// ClientID names the holder rather than the key. Several keys share one,
	// which is what makes deliberate rotation and "revoke everything this
	// caller has" possible — the questions that matter during an incident.
	ClientID   string     `json:"client_id"`
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

type CreateAPIKeyRequest struct {
	// ClientID identifies the caller that will hold the key. Required, so
	// that every credential can be traced back to a holder and revoked with
	// its siblings.
	//
	// None of these carry binding:"required". The handler validates them and
	// answers with a message naming the field; a binding failure would
	// collapse all of that into one generic "invalid request".
	ClientID string `json:"client_id"`
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
	ClientID   string     `json:"client_id"`
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

// RevokeClientKeysResponse reports what a revoke-by-client call took out, so
// the operator can see the blast radius of what they just did.
type RevokeClientKeysResponse struct {
	ClientID string           `json:"client_id"`
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
		ClientID:   k.ClientID,
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
