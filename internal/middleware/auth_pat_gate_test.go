package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"garde/internal/models"
	"garde/pkg/crypto"
	"garde/pkg/session"

	"github.com/gin-gonic/gin"
)

// authenticatePAT through the real middleware: valid, tampered and revoked
// tokens. Sessions and PATs share the Bearer scheme; shape decides the path.
func TestAuthenticatePATTable(t *testing.T) {
	svc, analyzer, repo := authStack(t)
	seedMiddlewareUser(t, repo)
	ctx := context.Background()

	plaintext, id, secretHash, err := crypto.GeneratePAT()
	if err != nil {
		t.Fatal(err)
	}
	token := &models.PersonalAccessToken{
		ID: id, UserID: "mw-1", Name: "ci", SecretHash: secretHash,
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.StorePAT(ctx, token); err != nil {
		t.Fatal(err)
	}
	mw := AuthMiddleware(svc, analyzer, repo)

	serve := func(presented string) (int, string) {
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.Use(mw)
		router.GET("/x", func(c *gin.Context) {
			patID, _ := c.Get(ContextPATID)
			uid, _ := c.Get("user_id")
			c.String(http.StatusOK, "pat=%v uid=%v", patID, uid)
		})
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("User-Agent", "test-agent")
		req.Header.Set("Authorization", "Bearer "+presented)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	code, body := serve(plaintext)
	if code != http.StatusOK {
		t.Fatalf("valid PAT: status = %d body = %q", code, body)
	}
	if body != "pat="+id+" uid=mw-1" {
		t.Fatalf("valid PAT body = %q", body)
	}

	tampered := plaintext[:len(plaintext)-1] + "A"
	if tampered == plaintext {
		tampered = plaintext[:len(plaintext)-1] + "B"
	}
	if code, _ := serve(tampered); code != http.StatusUnauthorized {
		t.Fatalf("tampered PAT: status = %d", code)
	}

	if _, err := repo.RevokePAT(ctx, id, "mw-1"); err != nil {
		t.Fatal(err)
	}
	if code, _ := serve(plaintext); code != http.StatusUnauthorized {
		t.Fatalf("revoked PAT: status = %d", code)
	}
}

func TestEnforceMFASetupGate(t *testing.T) {
	svc, analyzer, repo := authStack(t)
	ctx := context.Background()
	hash, err := crypto.HashPassword("DevAdminTest123!")
	if err != nil {
		t.Fatal(err)
	}
	u := &models.User{ID: "mw-enf", Email: "enf@example.com", PasswordHash: hash, Status: models.UserStatusOk, MFAEnforced: true}
	if err := repo.StoreUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Login(ctx, &models.LoginRequest{Email: "enf@example.com", Password: "DevAdminTest123!"}, "192.0.2.1", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	mw := AuthMiddleware(svc, analyzer, repo)

	serve := func(path string) int {
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.Use(mw)
		router.GET("/dashboard", func(c *gin.Context) { c.Status(http.StatusOK) })
		router.GET("/users/me", func(c *gin.Context) { c.Status(http.StatusOK) })
		router.GET("/users/mfa/setup", func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("User-Agent", "test-agent")
		req.AddCookie(&http.Cookie{Name: "session", Value: resp.SessionID})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := serve("/dashboard"); code != http.StatusForbidden {
		t.Fatalf("enforced user off the setup path: status = %d, want 403", code)
	}
	if code := serve("/users/me"); code != http.StatusOK {
		t.Fatalf("allowed path: status = %d", code)
	}
	if code := serve("/users/mfa/setup"); code != http.StatusOK {
		t.Fatalf("setup path: status = %d", code)
	}
}

func TestSecurityMiddlewareFloodIs429(t *testing.T) {
	svc, analyzer, repo := authStack(t)
	_ = svc
	mw := SecurityMiddleware(analyzer)
	ctx := context.Background()

	serve := func() int {
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.Use(mw)
		router.GET("/login", func(c *gin.Context) { c.Status(http.StatusOK) })
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req.Header.Set("User-Agent", "test-agent")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := serve(); code != http.StatusOK {
		t.Fatalf("clean client: status = %d", code)
	}

	// Pre-seed the sliding window past the 120/min default; the request must
	// then be refused before it is tracked.
	victim := session.HashString("192.0.2.1" + "test-agent")
	for i := 0; i < 130; i++ {
		if err := repo.IncrementRequestCount(ctx, victim, session.RapidRequestWindow); err != nil {
			t.Fatal(err)
		}
	}
	if code := serve(); code != http.StatusTooManyRequests {
		t.Fatalf("flooded client: status = %d, want 429", code)
	}
}
