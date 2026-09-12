package models

import "time"

// PersonalAccessToken is a credential a user issues to act as themselves on
// garde's APIs (scripts, CI). It is not a tenant /validate key: authentication
// loads the live user record, so permissions and groups follow the account.
//
// Bounds match service API keys: expiry is the default; immortality is opt-in.
const (
	DefaultPATTLL  = DefaultAPIKeyTTL
	MaxPATTLL      = MaxAPIKeyTTL
	MaxPATsPerUser = 25
)

type PersonalAccessToken struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	SecretHash string     `json:"secret_hash"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

func (t *PersonalAccessToken) Revoked() bool { return t.RevokedAt != nil }

func (t *PersonalAccessToken) Expired(now time.Time) bool {
	return t.ExpiresAt != nil && now.After(*t.ExpiresAt)
}

func (t *PersonalAccessToken) Usable(now time.Time) bool {
	return !t.Revoked() && !t.Expired(now)
}

type CreatePATRequest struct {
	Name string `json:"name"`
	// ExpiresIn is a Go duration such as "2160h". Omitted means DefaultPATTLL.
	ExpiresIn string `json:"expires_in,omitempty"`
	// NeverExpires opts out of expiry. Separate from omitting ExpiresIn so
	// immortality cannot happen by accident.
	NeverExpires bool `json:"never_expires,omitempty"`
}

type PATResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// CreatePATResponse is the only response that carries the plaintext token.
type CreatePATResponse struct {
	PATResponse
	Token string `json:"token"`
}

type ListPATsResponse struct {
	Tokens []PATResponse `json:"tokens"`
	Total  int           `json:"total"`
}

func NewPATResponse(t *PersonalAccessToken) PATResponse {
	return PATResponse{
		ID:         t.ID,
		Name:       t.Name,
		CreatedAt:  t.CreatedAt,
		ExpiresAt:  t.ExpiresAt,
		RevokedAt:  t.RevokedAt,
		LastUsedAt: t.LastUsedAt,
	}
}
