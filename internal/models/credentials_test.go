package models

import (
	"testing"
	"time"
)

func TestAPIKeyAudienceVocabulary(t *testing.T) {
	for _, info := range AllAPIKeyAudiences() {
		if !IsKnownAPIKeyAudience(info.Name) {
			t.Fatalf("AllAPIKeyAudiences lists %q which IsKnownAPIKeyAudience rejects", info.Name)
		}
		if info.Description == "" {
			t.Fatalf("audience %q has no description", info.Name)
		}
	}
	if IsKnownAPIKeyAudience("partner") {
		t.Fatal("unknown audience accepted")
	}
}

func TestServiceAPIKeyMatchesAudience(t *testing.T) {
	k := &ServiceAPIKey{Audience: AudienceTenant}
	if !k.MatchesAudience("") || !k.MatchesAudience(AudienceTenant) || k.MatchesAudience(AudienceInternal) {
		t.Fatal("tenant key audience matching wrong")
	}
	empty := &ServiceAPIKey{}
	if !empty.MatchesAudience(AudienceInternal) || !empty.MatchesAudience(AudienceTenant) {
		t.Fatal("empty audience must match any required surface")
	}
}

func TestAPIKeyScopeVocabularyLockstep(t *testing.T) {
	for _, info := range AllAPIKeyScopes() {
		if !IsKnownAPIKeyScope(info.Name) {
			t.Fatalf("AllAPIKeyScopes lists %q which IsKnownAPIKeyScope rejects", info.Name)
		}
		if info.Description == "" {
			t.Fatalf("scope %q has no description for the UI", info.Name)
		}
	}
	if !IsKnownAPIKeyScope(ScopeValidate) {
		t.Fatal("ScopeValidate must always be known")
	}
	if !IsKnownAPIKeyScope(ScopeAuth) {
		t.Fatal("ScopeAuth must always be known")
	}
	if IsKnownAPIKeyScope("admin") {
		t.Fatal("unknown scope accepted")
	}
}

func TestAPIKeyTTLBoundsSane(t *testing.T) {
	if DefaultAPIKeyTTL <= 0 || MaxAPIKeyTTL <= 0 {
		t.Fatal("TTLs must be positive")
	}
	if DefaultAPIKeyTTL > MaxAPIKeyTTL {
		t.Fatal("default TTL exceeds max TTL")
	}
	if DefaultPATTLL != DefaultAPIKeyTTL || MaxPATTLL != MaxAPIKeyTTL {
		t.Fatal("PAT bounds drifted from API-key bounds")
	}
}

func TestServiceAPIKeyLifecycle(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	k := &ServiceAPIKey{ID: "k", Scopes: []string{ScopeValidate}, ExpiresAt: &future}
	if !k.Usable(now) || k.Revoked() || k.Expired(now) {
		t.Fatal("fresh key not usable")
	}
	if !k.HasScope(ScopeValidate) || k.HasScope("admin") {
		t.Fatal("scope check wrong")
	}
	k.ExpiresAt = &past
	if k.Usable(now) || !k.Expired(now) {
		t.Fatal("expired key still usable")
	}
	k.ExpiresAt = nil
	revoked := now
	k.RevokedAt = &revoked
	if k.Usable(now) || !k.Revoked() {
		t.Fatal("revoked key still usable")
	}
	// No expiry at all (legacy/unspecified) means usable unless revoked.
	k.RevokedAt = nil
	if !k.Usable(now) {
		t.Fatal("key without expiry should be usable")
	}
}

func TestNewAPIKeyResponseNormalizesNilScopes(t *testing.T) {
	resp := NewAPIKeyResponse(&ServiceAPIKey{ID: "k", TenantID: "t", Name: "n"})
	if resp.Scopes == nil {
		t.Fatal("nil scopes must become [] for stable JSON")
	}
	if resp.ID != "k" || resp.TenantID != "t" || resp.Name != "n" {
		t.Fatalf("identity fields lost: %+v", resp)
	}
}

func TestPATLifecycle(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	p := &PersonalAccessToken{ID: "p", UserID: "u", ExpiresAt: &future}
	if !p.Usable(now) || p.Revoked() || p.Expired(now) {
		t.Fatal("fresh PAT not usable")
	}
	past := now.Add(-time.Hour)
	p.ExpiresAt = &past
	if p.Usable(now) {
		t.Fatal("expired PAT still usable")
	}
	if got := NewPATResponse(p); got.ID != "p" || got.Name != p.Name {
		t.Fatalf("response dropped fields: %+v", got)
	}
}

func TestMaxPATsPerUserPositive(t *testing.T) {
	if MaxPATsPerUser <= 0 {
		t.Fatal("quota must be positive")
	}
}
