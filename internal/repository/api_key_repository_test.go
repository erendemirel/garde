package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"garde/internal/models"
)

func storeKey(t *testing.T, repo *RedisRepository, id, name string) *models.ServiceAPIKey {
	t.Helper()
	key := &models.ServiceAPIKey{
		ID:         id,
		Name:       name,
		SecretHash: "hash-" + id,
		Scopes:     []string{models.ScopeValidate},
		CreatedAt:  time.Now().UTC(),
	}
	if err := repo.StoreServiceAPIKey(context.Background(), key); err != nil {
		t.Fatalf("StoreServiceAPIKey: %v", err)
	}
	return key
}

func storeClientKey(t *testing.T, repo *RedisRepository, id, clientID, name string) *models.ServiceAPIKey {
	t.Helper()
	key := &models.ServiceAPIKey{
		ID:         id,
		ClientID:   clientID,
		Name:       name,
		SecretHash: "hash-" + id,
		Scopes:     []string{models.ScopeValidate},
		CreatedAt:  time.Now().UTC(),
	}
	if err := repo.StoreServiceAPIKey(context.Background(), key); err != nil {
		t.Fatalf("StoreServiceAPIKey: %v", err)
	}
	return key
}

func TestListServiceAPIKeysByClient(t *testing.T) {
	repo, _ := newTestRepo(t)
	ctx := context.Background()

	storeClientKey(t, repo, "aa01", "acme", "acme-prod")
	storeClientKey(t, repo, "aa02", "acme", "acme-staging")
	storeClientKey(t, repo, "bb01", "globex", "globex-prod")

	acme, err := repo.ListServiceAPIKeysByClient(ctx, "acme")
	if err != nil {
		t.Fatalf("ListServiceAPIKeysByClient: %v", err)
	}
	if len(acme) != 2 {
		t.Fatalf("got %d keys, want 2", len(acme))
	}
	for _, key := range acme {
		if key.ClientID != "acme" {
			t.Fatalf("listing leaked a key held by %q", key.ClientID)
		}
	}

	none, err := repo.ListServiceAPIKeysByClient(ctx, "nobody")
	if err != nil {
		t.Fatalf("ListServiceAPIKeysByClient: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("got %d keys for an unknown client, want 0", len(none))
	}
}

// The incident-response path: one call takes out a compromised holder and
// leaves everyone else alone.
func TestRevokeServiceAPIKeysByClient(t *testing.T) {
	repo, _ := newTestRepo(t)
	ctx := context.Background()

	storeClientKey(t, repo, "aa01", "acme", "acme-prod")
	storeClientKey(t, repo, "aa02", "acme", "acme-staging")
	storeClientKey(t, repo, "bb01", "globex", "globex-prod")

	revoked, err := repo.RevokeServiceAPIKeysByClient(ctx, "acme")
	if err != nil {
		t.Fatalf("RevokeServiceAPIKeysByClient: %v", err)
	}
	if len(revoked) != 2 {
		t.Fatalf("revoked %d keys, want 2", len(revoked))
	}
	for _, key := range revoked {
		if !key.Revoked() {
			t.Fatalf("key %s came back unrevoked", key.ID)
		}
	}

	untouched, err := repo.GetServiceAPIKey(ctx, "bb01")
	if err != nil {
		t.Fatalf("GetServiceAPIKey: %v", err)
	}
	if untouched.Revoked() {
		t.Fatal("revoking one client's keys revoked another's")
	}
}

// Calling it twice must not fail or change the reported set, so that an
// operator can re-run it without wondering whether it worked the first time.
func TestRevokeServiceAPIKeysByClientIsIdempotent(t *testing.T) {
	repo, _ := newTestRepo(t)
	ctx := context.Background()

	storeClientKey(t, repo, "aa01", "acme", "acme-prod")

	if _, err := repo.RevokeServiceAPIKeysByClient(ctx, "acme"); err != nil {
		t.Fatalf("first revoke: %v", err)
	}

	again, err := repo.RevokeServiceAPIKeysByClient(ctx, "acme")
	if err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if len(again) != 1 || !again[0].Revoked() {
		t.Fatalf("second revoke reported %+v", again)
	}
}

func TestServiceAPIKeyStoreAndGet(t *testing.T) {
	repo, _ := newTestRepo(t)
	ctx := context.Background()

	storeKey(t, repo, "aabb", "billing")

	got, err := repo.GetServiceAPIKey(ctx, "aabb")
	if err != nil {
		t.Fatalf("GetServiceAPIKey: %v", err)
	}
	if got.Name != "billing" || got.SecretHash != "hash-aabb" {
		t.Fatalf("round trip lost fields: %+v", got)
	}
	if !got.HasScope(models.ScopeValidate) {
		t.Fatalf("scopes lost: %v", got.Scopes)
	}
	if got.LastUsedAt != nil {
		t.Fatal("a key that has never been used reports a last-used time")
	}
}

func TestServiceAPIKeyMissingIsDistinguishable(t *testing.T) {
	repo, _ := newTestRepo(t)

	_, err := repo.GetServiceAPIKey(context.Background(), "nope")
	if !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("err = %v, want ErrAPIKeyNotFound so the middleware can 401 rather than 500", err)
	}
}

func TestServiceAPIKeyTouchDoesNotRewriteRecord(t *testing.T) {
	repo, _ := newTestRepo(t)
	ctx := context.Background()

	storeKey(t, repo, "ccdd", "reporting")

	if err := repo.TouchServiceAPIKey(ctx, "ccdd"); err != nil {
		t.Fatalf("TouchServiceAPIKey: %v", err)
	}

	got, err := repo.GetServiceAPIKey(ctx, "ccdd")
	if err != nil {
		t.Fatalf("GetServiceAPIKey: %v", err)
	}
	if got.LastUsedAt == nil {
		t.Fatal("last-used time was not recorded")
	}
	// The record itself must be untouched, so concurrent requests bearing the
	// same key cannot clobber each other.
	if got.Name != "reporting" || got.SecretHash != "hash-ccdd" {
		t.Fatalf("touch damaged the record: %+v", got)
	}
}

func TestServiceAPIKeyRevokeIsIdempotentAndKeepsRecord(t *testing.T) {
	repo, _ := newTestRepo(t)
	ctx := context.Background()

	storeKey(t, repo, "eeff", "partner")

	revoked, err := repo.RevokeServiceAPIKey(ctx, "eeff")
	if err != nil {
		t.Fatalf("RevokeServiceAPIKey: %v", err)
	}
	if !revoked.Revoked() {
		t.Fatal("key does not report itself revoked")
	}
	first := *revoked.RevokedAt

	again, err := repo.RevokeServiceAPIKey(ctx, "eeff")
	if err != nil {
		t.Fatalf("second RevokeServiceAPIKey: %v", err)
	}
	if !again.RevokedAt.Equal(first) {
		t.Fatal("revoking twice moved the revocation time")
	}

	// The record survives revocation so it stays visible in the listing.
	stored, err := repo.GetServiceAPIKey(ctx, "eeff")
	if err != nil {
		t.Fatalf("revoked key disappeared: %v", err)
	}
	if stored.Usable(time.Now().UTC()) {
		t.Fatal("a revoked key still reports itself usable")
	}
}

func TestServiceAPIKeyRevokeUnknownID(t *testing.T) {
	repo, _ := newTestRepo(t)

	if _, err := repo.RevokeServiceAPIKey(context.Background(), "missing"); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("err = %v, want ErrAPIKeyNotFound", err)
	}
}

func TestServiceAPIKeyListIsNewestFirst(t *testing.T) {
	repo, _ := newTestRepo(t)
	ctx := context.Background()

	older := &models.ServiceAPIKey{ID: "1111", Name: "older", CreatedAt: time.Now().UTC().Add(-time.Hour)}
	newer := &models.ServiceAPIKey{ID: "2222", Name: "newer", CreatedAt: time.Now().UTC()}
	for _, key := range []*models.ServiceAPIKey{older, newer} {
		if err := repo.StoreServiceAPIKey(ctx, key); err != nil {
			t.Fatal(err)
		}
	}

	keys, err := repo.ListServiceAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListServiceAPIKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("listed %d keys, want 2", len(keys))
	}
	if keys[0].Name != "newer" || keys[1].Name != "older" {
		t.Fatalf("order = %s, %s", keys[0].Name, keys[1].Name)
	}
}

func TestServiceAPIKeyListIgnoresLastUsedMarkers(t *testing.T) {
	repo, _ := newTestRepo(t)
	ctx := context.Background()

	storeKey(t, repo, "abcd", "one")
	if err := repo.TouchServiceAPIKey(ctx, "abcd"); err != nil {
		t.Fatal(err)
	}

	// The marker lives under its own prefix; the scan must not mistake it for
	// a second key.
	keys, err := repo.ListServiceAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListServiceAPIKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("listed %d keys, want 1", len(keys))
	}
}

func TestServiceAPIKeyDeleteRemovesMarker(t *testing.T) {
	repo, _ := newTestRepo(t)
	ctx := context.Background()

	storeKey(t, repo, "dead", "gone")
	if err := repo.TouchServiceAPIKey(ctx, "dead"); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteServiceAPIKey(ctx, "dead"); err != nil {
		t.Fatalf("DeleteServiceAPIKey: %v", err)
	}

	if _, err := repo.GetServiceAPIKey(ctx, "dead"); !errors.Is(err, ErrAPIKeyNotFound) {
		t.Fatalf("err = %v, want ErrAPIKeyNotFound", err)
	}

	// A re-issued key must not inherit the deleted key's last-used time.
	storeKey(t, repo, "dead", "reissued")
	got, err := repo.GetServiceAPIKey(ctx, "dead")
	if err != nil {
		t.Fatal(err)
	}
	if got.LastUsedAt != nil {
		t.Fatal("a re-issued key inherited the old last-used marker")
	}
}

func TestServiceAPIKeyExpiry(t *testing.T) {
	past := time.Now().UTC().Add(-time.Minute)
	future := time.Now().UTC().Add(time.Hour)
	now := time.Now().UTC()

	expired := &models.ServiceAPIKey{ExpiresAt: &past}
	if expired.Usable(now) {
		t.Fatal("an expired key reports itself usable")
	}

	live := &models.ServiceAPIKey{ExpiresAt: &future}
	if !live.Usable(now) {
		t.Fatal("a key expiring in an hour reports itself unusable")
	}

	never := &models.ServiceAPIKey{}
	if !never.Usable(now) {
		t.Fatal("a key with no expiry reports itself unusable")
	}
}
