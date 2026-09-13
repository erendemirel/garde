package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"garde/internal/models"
	"garde/internal/repository"
	"garde/internal/service"
	"garde/internal/testutil"
	"garde/pkg/crypto"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware with a real service on miniredis: cookie and Bearer session
// paths, plus every missing/malformed credential shape.
func authStack(t *testing.T) (*service.AuthService, *service.SecurityAnalyzer, *repository.RedisRepository) {
	t.Helper()
	testutil.InitConfig(t, map[string]string{"superuser_email": "root@example.com"})
	_, client := testutil.NewMiniRedis(t)
	repo := repository.NewRedisRepositoryFromClient(client)
	svc := service.NewAuthService(repo)
	return svc, service.NewSecurityAnalyzer(repo), repo
}

func seedMiddlewareUser(t *testing.T, repo *repository.RedisRepository) {
	t.Helper()
	hash, err := crypto.HashPassword("DevAdminTest123!")
	if err != nil {
		t.Fatal(err)
	}
	u := &models.User{ID: "mw-1", Email: "mw@example.com", PasswordHash: hash, Status: models.UserStatusOk}
	if err := repo.StoreUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
}

func serveAuthed(t *testing.T, mw gin.HandlerFunc, setup func(req *http.Request)) (int, string, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(mw)
	router.GET("/x", func(c *gin.Context) {
		uid, _ := c.Get("user_id")
		c.String(http.StatusOK, "uid=%v admin=%v super=%v", uid, c.GetBool("is_admin"), c.GetBool("is_superuser"))
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("User-Agent", "test-agent")
	if setup != nil {
		setup(req)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), rec.Header().Get("Set-Cookie")
}

func TestAuthMiddlewareSessionCookieTable(t *testing.T) {
	svc, analyzer, repo := authStack(t)
	seedMiddlewareUser(t, repo)
	ctx := context.Background()
	resp, err := svc.Login(ctx, &models.LoginRequest{Email: "mw@example.com", Password: "DevAdminTest123!"}, "192.0.2.1", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	mw := AuthMiddleware(svc, analyzer, repo)

	code, body, _ := serveAuthed(t, mw, func(req *http.Request) {
		req.AddCookie(&http.Cookie{Name: "session", Value: resp.SessionID})
	})
	if code != http.StatusOK || body != "uid=mw-1 admin=false super=false" {
		t.Fatalf("valid cookie: status = %d body = %q", code, body)
	}

	code, _, cookie := serveAuthed(t, mw, func(req *http.Request) {
		req.AddCookie(&http.Cookie{Name: "session", Value: strings.Repeat("A", 86)})
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("bad cookie: status = %d", code)
	}
	if cookie == "" {
		t.Fatal("bad session must clear the cookie")
	}

	code, _, _ = serveAuthed(t, mw, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("missing credential: status = %d", code)
	}

	code, _, _ = serveAuthed(t, mw, func(req *http.Request) {
		req.AddCookie(&http.Cookie{Name: "session", Value: resp.SessionID})
		req.Header.Set("Authorization", "Bearer "+resp.SessionID)
	})
	if code != http.StatusBadRequest {
		t.Fatalf("cookie+bearer conflict: status = %d", code)
	}
}

func TestAuthMiddlewareBearerTable(t *testing.T) {
	svc, analyzer, repo := authStack(t)
	seedMiddlewareUser(t, repo)
	ctx := context.Background()
	resp, err := svc.Login(ctx, &models.LoginRequest{Email: "mw@example.com", Password: "DevAdminTest123!"}, "192.0.2.1", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	mw := AuthMiddleware(svc, analyzer, repo)

	code, body, _ := serveAuthed(t, mw, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+resp.SessionID)
	})
	if code != http.StatusOK || body != "uid=mw-1 admin=false super=false" {
		t.Fatalf("valid bearer: status = %d body = %q", code, body)
	}

	code, _, _ = serveAuthed(t, mw, func(req *http.Request) {
		req.Header.Set("Authorization", "Token "+resp.SessionID)
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("malformed scheme: status = %d", code)
	}
}
