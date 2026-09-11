package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"garde/internal/models"
	"garde/internal/repository"
	"garde/pkg/config"
	"garde/pkg/crypto"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

const legacyTestKey = "TestApiKey123!TestApiKey123!"

func withLegacyKey(t *testing.T, value string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "api_key"), []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
}

func newKeyRepo(t *testing.T) *repository.RedisRepository {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return repository.NewRedisRepositoryFromClient(client)
}

// issueKey mints a real key through the same path the admin handler uses and
// returns the plaintext the caller would present.
func issueKey(t *testing.T, repo *repository.RedisRepository, mutate func(*models.ServiceAPIKey)) string {
	t.Helper()
	plaintext, id, hash, err := crypto.GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	key := &models.ServiceAPIKey{
		ID:         id,
		Name:       "tenant",
		SecretHash: hash,
		Scopes:     []string{models.ScopeValidate},
		CreatedAt:  time.Now().UTC(),
	}
	if mutate != nil {
		mutate(key)
	}
	if err := repo.StoreServiceAPIKey(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	return plaintext
}

type authResult struct {
	status    int
	reached   bool
	keyID     string
	keyName   string
	rateLimit int
}

func runAPIKeyAuth(t *testing.T, opts APIKeyAuthOptions, presented string) authResult {
	t.Helper()
	gin.SetMode(gin.TestMode)

	var res authResult
	router := gin.New()
	router.GET("/validate", APIKeyAuth(opts), func(c *gin.Context) {
		res.reached = true
		res.keyID = c.GetString(ContextAPIKeyID)
		res.keyName = c.GetString(ContextAPIKeyName)
		res.rateLimit = c.GetInt(contextAPIKeyRateLimit)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/validate", nil)
	if presented != "" {
		req.Header.Set(APIKeyHeader, presented)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	res.status = w.Code
	return res
}

func TestAPIKeyAuthAcceptsTenantKey(t *testing.T) {
	withLegacyKey(t, legacyTestKey)
	repo := newKeyRepo(t)
	presented := issueKey(t, repo, func(k *models.ServiceAPIKey) {
		k.Name = "billing"
		k.RateLimit = 42
	})

	res := runAPIKeyAuth(t, APIKeyAuthOptions{
		Repo:          repo,
		RequiredScope: models.ScopeValidate,
	}, presented)

	if !res.reached || res.status != http.StatusOK {
		t.Fatalf("status=%d reached=%v, want an authenticated request", res.status, res.reached)
	}
	if res.keyID == "" {
		t.Fatal("the key id was not put on the context, so per-key rate limiting cannot work")
	}
	if res.keyName != "billing" {
		t.Fatalf("keyName = %q, want billing", res.keyName)
	}
	if res.rateLimit != 42 {
		t.Fatalf("rateLimit = %d, want the key's own 42", res.rateLimit)
	}
}

// The whole point of per-tenant keys: the shared secret must not open the
// public listener, or nothing has been gained over the previous design.
func TestAPIKeyAuthRejectsLegacyKeyWhenNotAllowed(t *testing.T) {
	withLegacyKey(t, legacyTestKey)
	repo := newKeyRepo(t)

	res := runAPIKeyAuth(t, APIKeyAuthOptions{
		Repo:           repo,
		AllowLegacyKey: false,
		RequiredScope:  models.ScopeValidate,
	}, legacyTestKey)

	if res.reached || res.status != http.StatusUnauthorized {
		t.Fatalf("status=%d reached=%v, want 401 for the shared key", res.status, res.reached)
	}
}

func TestAPIKeyAuthAcceptsLegacyKeyWhenAllowed(t *testing.T) {
	withLegacyKey(t, legacyTestKey)

	// No repo: this is the single-listener and mesh-listener shape, where the
	// shared key is the only credential.
	res := runAPIKeyAuth(t, APIKeyAuthOptions{AllowLegacyKey: true}, legacyTestKey)

	if !res.reached || res.status != http.StatusOK {
		t.Fatalf("status=%d reached=%v, want the shared key to authenticate", res.status, res.reached)
	}
	if res.keyID != "" {
		t.Fatal("the shared key must not claim a per-tenant identity")
	}
}

func TestAPIKeyAuthTenantKeyNeedsAStore(t *testing.T) {
	withLegacyKey(t, legacyTestKey)
	repo := newKeyRepo(t)
	presented := issueKey(t, repo, nil)

	// A listener with no key store must refuse a per-tenant key rather than
	// fall through to comparing it against the shared secret.
	res := runAPIKeyAuth(t, APIKeyAuthOptions{Repo: nil, AllowLegacyKey: true}, presented)

	if res.reached || res.status != http.StatusUnauthorized {
		t.Fatalf("status=%d reached=%v, want 401", res.status, res.reached)
	}
}

func TestAPIKeyAuthRejectsUnusableAndUnknownKeys(t *testing.T) {
	withLegacyKey(t, legacyTestKey)

	revokedAt := time.Now().UTC().Add(-time.Minute)
	expiredAt := time.Now().UTC().Add(-time.Minute)

	cases := []struct {
		name    string
		mutate  func(*models.ServiceAPIKey)
		tamper  func(string) string
		want    int
		wantWhy string
	}{
		{
			name:    "revoked",
			mutate:  func(k *models.ServiceAPIKey) { k.RevokedAt = &revokedAt },
			want:    http.StatusUnauthorized,
			wantWhy: "a revoked key must stop working",
		},
		{
			name:    "expired",
			mutate:  func(k *models.ServiceAPIKey) { k.ExpiresAt = &expiredAt },
			want:    http.StatusUnauthorized,
			wantWhy: "an expired key must stop working",
		},
		{
			name:    "missing scope",
			mutate:  func(k *models.ServiceAPIKey) { k.Scopes = nil },
			want:    http.StatusForbidden,
			wantWhy: "a key without the validate scope must not reach the handler",
		},
		{
			name:    "wrong secret for a real id",
			tamper:  func(p string) string { return p + "x" },
			want:    http.StatusUnauthorized,
			wantWhy: "the secret half must be verified, not just the id",
		},
		{
			name:    "unknown id",
			tamper:  func(string) string { return "garde_00112233445566ff_c2VjcmV0LXRoYXQtaXMtbm90LXJlYWw" },
			want:    http.StatusUnauthorized,
			wantWhy: "an id that was never issued must be refused",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newKeyRepo(t)
			presented := issueKey(t, repo, tc.mutate)
			if tc.tamper != nil {
				presented = tc.tamper(presented)
			}

			res := runAPIKeyAuth(t, APIKeyAuthOptions{
				Repo:          repo,
				RequiredScope: models.ScopeValidate,
			}, presented)

			if res.reached {
				t.Fatalf("%s: the request reached the handler", tc.wantWhy)
			}
			if res.status != tc.want {
				t.Fatalf("status = %d, want %d (%s)", res.status, tc.want, tc.wantWhy)
			}
		})
	}
}

func TestAPIKeyAuthRejectsMissingHeader(t *testing.T) {
	withLegacyKey(t, legacyTestKey)
	repo := newKeyRepo(t)

	res := runAPIKeyAuth(t, APIKeyAuthOptions{Repo: repo, AllowLegacyKey: true}, "")

	if res.reached || res.status != http.StatusUnauthorized {
		t.Fatalf("status=%d reached=%v, want 401", res.status, res.reached)
	}
}

// An unset API_KEY must not let an empty or arbitrary header through, which a
// naive constant-time compare of two empty strings would do.
func TestAPIKeyAuthUnsetLegacyKeyNeverAuthenticates(t *testing.T) {
	withLegacyKey(t, "")

	for _, presented := range []string{"anything", legacyTestKey} {
		res := runAPIKeyAuth(t, APIKeyAuthOptions{AllowLegacyKey: true}, presented)
		if res.reached || res.status != http.StatusUnauthorized {
			t.Fatalf("presented %q: status=%d reached=%v, want 401", presented, res.status, res.reached)
		}
	}
}

func TestAPIKeyAuthRecordsUse(t *testing.T) {
	withLegacyKey(t, legacyTestKey)
	repo := newKeyRepo(t)
	presented := issueKey(t, repo, nil)

	id, _, ok := crypto.ParseAPIKey(presented)
	if !ok {
		t.Fatal("could not parse the key we just issued")
	}

	before, err := repo.GetServiceAPIKey(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if before.LastUsedAt != nil {
		t.Fatal("an unused key already reports a last-used time")
	}

	if res := runAPIKeyAuth(t, APIKeyAuthOptions{Repo: repo, RequiredScope: models.ScopeValidate}, presented); !res.reached {
		t.Fatalf("status=%d, want the request to authenticate", res.status)
	}

	after, err := repo.GetServiceAPIKey(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if after.LastUsedAt == nil {
		t.Fatal("use was not recorded, so an idle credential cannot be spotted")
	}
}
