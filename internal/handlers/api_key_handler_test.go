package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"garde/internal/models"
	"garde/internal/repository"
	pkgerrors "garde/pkg/errors"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

func newAPIKeyTestHandler(t *testing.T) *APIKeyHandler {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewAPIKeyHandler(repository.NewRedisRepositoryFromClient(client))
}

// apiKeyRouter mounts the routes with a superuser already in context, since
// the tier check belongs to middleware that is tested elsewhere.
func apiKeyRouter(h *APIKeyHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "root-1")
		c.Next()
	})
	router.POST("/admin/api-keys", h.CreateAPIKey)
	router.GET("/admin/api-keys", h.ListAPIKeys)
	router.GET("/admin/api-key-scopes", h.ListAPIKeyScopes)
	router.DELETE("/admin/tenants/:tenant_id/api-keys", h.RevokeTenantAPIKeys)
	return router
}

func postKey(t *testing.T, router *gin.Engine, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/api-keys", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// decodeKey pulls the issued key out of a success envelope.
func decodeKey(t *testing.T, rec *httptest.ResponseRecorder) models.CreateAPIKeyResponse {
	t.Helper()
	var envelope struct {
		Data models.CreateAPIKeyResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return envelope.Data
}

func errorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var envelope struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return envelope.Error.Message
}

// Least privilege: a key asked for with no scopes must be refused, not
// quietly granted one.
func TestCreateAPIKeyRequiresExplicitScopes(t *testing.T) {
	router := apiKeyRouter(newAPIKeyTestHandler(t))

	for _, body := range []map[string]any{
		{"tenant_id": "acme", "name": "acme-prod"},
		{"tenant_id": "acme", "name": "acme-prod", "scopes": []string{}},
	} {
		rec := postKey(t, router, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 for %v", rec.Code, body)
		}
		if got := errorMessage(t, rec); got != pkgerrors.ErrAPIKeyScopesRequired {
			t.Fatalf("message = %q, want %q", got, pkgerrors.ErrAPIKeyScopesRequired)
		}
	}
}

func TestCreateAPIKeyRequiresTenantID(t *testing.T) {
	router := apiKeyRouter(newAPIKeyTestHandler(t))

	rec := postKey(t, router, map[string]any{
		"name":   "acme-prod",
		"scopes": []string{models.ScopeValidate},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := errorMessage(t, rec); got != pkgerrors.ErrInvalidAPIKeyTenantID {
		t.Fatalf("message = %q, want %q", got, pkgerrors.ErrInvalidAPIKeyTenantID)
	}
}

// Omitting expires_in must mean the default lifetime, not immortality.
func TestCreateAPIKeyExpiresByDefault(t *testing.T) {
	router := apiKeyRouter(newAPIKeyTestHandler(t))

	rec := postKey(t, router, map[string]any{
		"tenant_id": "acme",
		"name":      "acme-prod",
		"scopes":    []string{models.ScopeValidate},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}

	key := decodeKey(t, rec)
	if key.ExpiresAt == nil {
		t.Fatal("a key issued without expires_in never expires; the default must be bounded")
	}
	if remaining := time.Until(*key.ExpiresAt); remaining > models.DefaultAPIKeyTTL+time.Minute {
		t.Fatalf("expiry is %v away, want about %v", remaining, models.DefaultAPIKeyTTL)
	}
	if key.TenantID != "acme" {
		t.Fatalf("tenant_id = %q, want acme", key.TenantID)
	}
}

func TestCreateAPIKeyNeverExpiresIsDeliberate(t *testing.T) {
	router := apiKeyRouter(newAPIKeyTestHandler(t))

	rec := postKey(t, router, map[string]any{
		"tenant_id":     "acme",
		"name":          "acme-forever",
		"scopes":        []string{models.ScopeValidate},
		"never_expires": true,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	if decodeKey(t, rec).ExpiresAt != nil {
		t.Fatal("never_expires was asked for but an expiry was set anyway")
	}
}

// One call has to take out everything a compromised holder has.
func TestRevokeTenantAPIKeysRevokesOnlyThatTenant(t *testing.T) {
	handler := newAPIKeyTestHandler(t)
	router := apiKeyRouter(handler)

	for _, spec := range []struct{ tenant, name string }{
		{"acme", "acme-prod"},
		{"acme", "acme-staging"},
		{"globex", "globex-prod"},
	} {
		rec := postKey(t, router, map[string]any{
			"tenant_id": spec.tenant,
			"name":      spec.name,
			"scopes":    []string{models.ScopeValidate},
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("issuing %s: %s", spec.name, rec.Body.String())
		}
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/admin/tenants/acme/api-keys", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var envelope struct {
		Data models.RevokeTenantKeysResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.Revoked != 2 {
		t.Fatalf("revoked = %d, want 2", envelope.Data.Revoked)
	}
	for _, key := range envelope.Data.Keys {
		if key.RevokedAt == nil {
			t.Fatalf("key %s came back without a revocation time", key.ID)
		}
	}

	// The other holder must be untouched.
	remaining, err := handler.repo.ListServiceAPIKeysByTenant(context.Background(), "globex")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].Revoked() {
		t.Fatalf("globex keys were affected: %+v", remaining)
	}
}

func TestRevokeTenantAPIKeysWithNoKeys(t *testing.T) {
	router := apiKeyRouter(newAPIKeyTestHandler(t))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/admin/tenants/nobody/api-keys", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestResolveAPIKeyExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		req      models.CreateAPIKeyRequest
		wantErr  string
		wantNil  bool
		wantFrom time.Duration
	}{
		{
			name:     "omitted falls back to the default lifetime",
			req:      models.CreateAPIKeyRequest{},
			wantFrom: models.DefaultAPIKeyTTL,
		},
		{
			name:     "an explicit duration is honoured",
			req:      models.CreateAPIKeyRequest{ExpiresIn: "24h"},
			wantFrom: 24 * time.Hour,
		},
		{
			name:    "never_expires yields no expiry",
			req:     models.CreateAPIKeyRequest{NeverExpires: true},
			wantNil: true,
		},
		{
			name:    "both fields together is ambiguous",
			req:     models.CreateAPIKeyRequest{ExpiresIn: "24h", NeverExpires: true},
			wantErr: pkgerrors.ErrAPIKeyExpiryConflict,
		},
		{
			// Otherwise the ceiling could be sidestepped by asking for a century.
			name:    "past the ceiling is refused",
			req:     models.CreateAPIKeyRequest{ExpiresIn: "9000h"},
			wantErr: pkgerrors.ErrAPIKeyExpiryTooLong,
		},
		{
			name:    "unparseable duration",
			req:     models.CreateAPIKeyRequest{ExpiresIn: "soon"},
			wantErr: pkgerrors.ErrInvalidAPIKeyExpiry,
		},
		{
			name:    "zero duration",
			req:     models.CreateAPIKeyRequest{ExpiresIn: "0h"},
			wantErr: pkgerrors.ErrInvalidAPIKeyExpiry,
		},
		{
			name:    "negative duration",
			req:     models.CreateAPIKeyRequest{ExpiresIn: "-24h"},
			wantErr: pkgerrors.ErrInvalidAPIKeyExpiry,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, errMsg := resolveAPIKeyExpiry(&tc.req, now)

			if tc.wantErr != "" {
				if errMsg != tc.wantErr {
					t.Fatalf("error = %q, want %q", errMsg, tc.wantErr)
				}
				return
			}
			if errMsg != "" {
				t.Fatalf("unexpected error %q", errMsg)
			}
			if tc.wantNil {
				if got != nil {
					t.Fatalf("expiry = %v, want none", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expiry = none, want a bounded time")
			}
			if want := now.Add(tc.wantFrom); !got.Equal(want) {
				t.Fatalf("expiry = %v, want %v", got, want)
			}
		})
	}
}

// The UI sources this list rather than hardcoding names. An empty response
// would leave the issue form unable to grant anything.
func TestListAPIKeyScopes(t *testing.T) {
	router := apiKeyRouter(newAPIKeyTestHandler(t))
	req := httptest.NewRequest(http.MethodGet, "/admin/api-key-scopes", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var envelope struct {
		Data []models.APIKeyScopeInfo `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Data) == 0 {
		t.Fatal("expected at least one grantable scope")
	}
	for _, scope := range envelope.Data {
		if !models.IsKnownAPIKeyScope(scope.Name) {
			t.Fatalf("listed scope %q is not accepted by IsKnownAPIKeyScope", scope.Name)
		}
		if scope.Description == "" {
			t.Fatalf("scope %q has no description for the UI", scope.Name)
		}
	}
}
