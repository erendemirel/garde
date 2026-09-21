package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"garde/internal/models"
	"garde/internal/repository"
	"garde/internal/testutil"
	"garde/pkg/config"
	pkgerrors "garde/pkg/errors"

	"github.com/gin-gonic/gin"
)

func initCapSecrets(t *testing.T, secrets map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, value := range secrets {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatalf("write secret %s: %v", name, err)
		}
	}
	if err := config.Init(dir); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
}

func TestCapMiddlewareDisabledPasses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initCapSecrets(t, map[string]string{"cap_enabled": "false"})

	router := gin.New()
	router.POST("/login", CapMiddleware(nil), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestCapMiddlewareLoginAllowsFirstAttemptWithoutToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	_, client := testutil.NewMiniRedis(t)
	repo := repository.NewStoreFromClients(nil, client)
	initCapSecrets(t, map[string]string{
		"cap_enabled":    "true",
		"cap_site_key":   "sitekey",
		"cap_secret_key": "secret",
		"cap_api_url":    "http://127.0.0.1:9",
	})

	router := gin.New()
	router.POST("/login",
		func(c *gin.Context) {
			c.Set(ContextKeyValidatedRequest, models.LoginRequest{
				Email:    "a@example.com",
				Password: "DevAdminTest123!",
			})
			c.Next()
		},
		CapMiddleware(repo),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
	)

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.1.1.1:1234"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 on first login attempt; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCapMiddlewareLoginRequiresTokenAfterFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	_, client := testutil.NewMiniRedis(t)
	repo := repository.NewStoreFromClients(nil, client)
	initCapSecrets(t, map[string]string{
		"cap_enabled":    "true",
		"cap_site_key":   "sitekey",
		"cap_secret_key": "secret",
		"cap_api_url":    "http://127.0.0.1:9",
	})

	ctx := t.Context()
	if _, err := repo.RecordFailedLogin(ctx, "a@example.com", "10.2.2.2"); err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.POST("/login",
		func(c *gin.Context) {
			c.Set(ContextKeyValidatedRequest, models.LoginRequest{
				Email:    "a@example.com",
				Password: "DevAdminTest123!",
			})
			c.Next()
		},
		CapMiddleware(repo),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
	)

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.2.2.2:1234"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 after prior failure", rec.Code)
	}

	var body models.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Details.Message != pkgerrors.ErrCaptchaRequired {
		t.Fatalf("message = %q, want %q", body.Details.Message, pkgerrors.ErrCaptchaRequired)
	}
}

func TestCapMiddlewareRegisterRequiresTokenWhenEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initCapSecrets(t, map[string]string{
		"cap_enabled":    "true",
		"cap_site_key":   "sitekey",
		"cap_secret_key": "secret",
		"cap_api_url":    "http://127.0.0.1:9",
	})

	router := gin.New()
	router.POST("/users", CapMiddleware(nil), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/users", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	var body models.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Details.Message != pkgerrors.ErrCaptchaRequired {
		t.Fatalf("message = %q, want %q", body.Details.Message, pkgerrors.ErrCaptchaRequired)
	}
}

func TestCapMiddlewareAcceptsHeaderTokenViaSiteverify(t *testing.T) {
	gin.SetMode(gin.TestMode)
	_, client := testutil.NewMiniRedis(t)
	repo := repository.NewStoreFromClients(nil, client)

	mux := http.NewServeMux()
	mux.HandleFunc("/sitekey/siteverify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	initCapSecrets(t, map[string]string{
		"cap_enabled":    "true",
		"cap_site_key":   "sitekey",
		"cap_secret_key": "secret",
		"cap_api_url":    srv.URL,
	})

	if _, err := repo.RecordFailedLogin(t.Context(), "a@example.com", "10.3.3.3"); err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.POST("/login",
		func(c *gin.Context) {
			c.Set(ContextKeyValidatedRequest, models.LoginRequest{Email: "a@example.com"})
			c.Next()
		},
		CapMiddleware(repo),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
	)

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "10.3.3.3:1234"
	req.Header.Set(capTokenHeader, "tok")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCapMiddlewareRejectsFailedSiteverify(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mux := http.NewServeMux()
	mux.HandleFunc("/sitekey/siteverify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	initCapSecrets(t, map[string]string{
		"cap_enabled":    "true",
		"cap_site_key":   "sitekey",
		"cap_secret_key": "secret",
		"cap_api_url":    srv.URL,
	})

	router := gin.New()
	router.POST("/users", CapMiddleware(nil), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/users", nil)
	req.Header.Set(capTokenHeader, "bad-tok")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	var body models.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Details.Message != pkgerrors.ErrCaptchaFailed {
		t.Fatalf("message = %q, want %q", body.Details.Message, pkgerrors.ErrCaptchaFailed)
	}
}

func TestCapMiddlewareAcceptsBodyTokenWhenEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var gotSecret, gotResponse string
	mux := http.NewServeMux()
	mux.HandleFunc("/sitekey/siteverify", func(w http.ResponseWriter, r *http.Request) {
		var payload capVerifyRequest
		_ = json.NewDecoder(r.Body).Decode(&payload)
		gotSecret = payload.Secret
		gotResponse = payload.Response
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	initCapSecrets(t, map[string]string{
		"cap_enabled":    "true",
		"cap_site_key":   "sitekey",
		"cap_secret_key": "secret-value",
		"cap_api_url":    srv.URL,
	})

	router := gin.New()
	router.POST("/users",
		func(c *gin.Context) {
			c.Set(ContextKeyValidatedRequest, models.CreateUserRequest{
				Email:    "a@example.com",
				Password: "DevAdminTest123!",
				CapToken: "body-token",
			})
			c.Next()
		},
		CapMiddleware(nil),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
	)

	req := httptest.NewRequest(http.MethodPost, "/users", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if gotSecret != "secret-value" || gotResponse != "body-token" {
		t.Fatalf("siteverify payload secret=%q response=%q", gotSecret, gotResponse)
	}
}

func TestCapMiddlewareAcceptsBypassToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initCapSecrets(t, map[string]string{
		"cap_enabled":      "true",
		"cap_site_key":     "sitekey",
		"cap_secret_key":   "secret",
		"cap_api_url":      "http://127.0.0.1:9",
		"cap_bypass_token": "e2e-cap-bypass-token",
	})

	router := gin.New()
	router.POST("/users", CapMiddleware(nil), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/users", nil)
	req.Header.Set(capTokenHeader, "e2e-cap-bypass-token")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCapMiddlewareSkipsWhenAuthScopedAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := testutil.NewTestStore(t)
	initCapSecrets(t, map[string]string{
		"cap_enabled":    "true",
		"cap_site_key":   "sitekey",
		"cap_secret_key": "secret",
		"cap_api_url":    "http://127.0.0.1:9",
	})

	presented := issueKey(t, repo, func(k *models.ServiceAPIKey) {
		k.Scopes = []string{models.ScopeAuth}
	})

	router := gin.New()
	router.POST("/users", CapMiddleware(repo), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/users", nil)
	req.Header.Set(APIKeyHeader, presented)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with auth-scoped key; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCapMiddlewareStillRequiresTokenForValidateOnlyAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := testutil.NewTestStore(t)
	initCapSecrets(t, map[string]string{
		"cap_enabled":    "true",
		"cap_site_key":   "sitekey",
		"cap_secret_key": "secret",
		"cap_api_url":    "http://127.0.0.1:9",
	})

	presented := issueKey(t, repo, func(k *models.ServiceAPIKey) {
		k.Scopes = []string{models.ScopeValidate}
	})

	router := gin.New()
	router.POST("/users", CapMiddleware(repo), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/users", nil)
	req.Header.Set(APIKeyHeader, presented)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for validate-only key", rec.Code)
	}
}

func TestExtractCapTokenFromValidatedRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/login", nil)
	c.Set(ContextKeyValidatedRequest, models.LoginRequest{CapToken: " from-body "})
	if got := extractCapToken(c); got != "from-body" {
		t.Fatalf("extractCapToken = %q, want from-body", got)
	}
}
