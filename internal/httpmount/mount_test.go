package httpmount

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"garde/internal/handlers"
	"garde/internal/middleware"
	"garde/internal/service"
	"garde/internal/testutil"
	"garde/pkg/config"

	"github.com/gin-gonic/gin"
)

func testEngine(t *testing.T) (*gin.Engine, *Deps) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	repo := testutil.NewTestStore(t)
	auth := service.NewAuthService(repo)
	deps := &Deps{
		Repo:             repo,
		AuthService:      auth,
		SecurityAnalyzer: service.NewSecurityAnalyzer(repo),
		AuthHandler:      handlers.NewAuthHandler(auth),
		APIKeyHandler:    handlers.NewAPIKeyHandler(repo),
		PATHandler:       handlers.NewPATHandler(repo),
		CaptchaHandler:   handlers.NewCaptchaHandler(repo),
		RateLimiter:      middleware.NewRateLimiter(repo),
	}
	r := gin.New()
	r.Use(middleware.Recovery())
	return r, deps
}

func routeExists(r http.Handler, method, path string) bool {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	r.ServeHTTP(rec, req)
	// Gin returns 404 for unknown routes; 401/403/400/200/204/405 mean mounted.
	return rec.Code != http.StatusNotFound
}

func TestPublicKillSwitchOmitsAuthRoutes(t *testing.T) {
	testutil.InitConfig(t, map[string]string{
		"public_self_service": "false",
		"service_listener":    "true",
		"mfa_encryption_key":  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"superuser_email":     "root@example.com",
	})
	r, deps := testEngine(t)
	MountPublicListener(r, deps)

	if !routeExists(r, http.MethodGet, "/public/config") {
		t.Fatal("expected /public/config on public listener")
	}
	for _, path := range []string{"/login", "/users", "/users/me", "/users/password/otp", "/validate", "/admin/api-keys"} {
		if routeExists(r, http.MethodPost, path) || routeExists(r, http.MethodGet, path) {
			t.Fatalf("kill switch on: public must not serve %s", path)
		}
	}
}

func TestPublicOpenMountsExternalNotAdminWhenServiceListener(t *testing.T) {
	testutil.InitConfig(t, map[string]string{
		"public_self_service": "true",
		"service_listener":    "true",
		"public_validate":     "false",
		"mfa_encryption_key":  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"superuser_email":     "root@example.com",
	})
	r, deps := testEngine(t)
	MountPublicListener(r, deps)

	if !routeExists(r, http.MethodPost, "/login") {
		t.Fatal("expected /login on public when kill switch off")
	}
	if routeExists(r, http.MethodGet, "/admin/api-keys") {
		t.Fatal("admin must not mount on public when service listener is on")
	}
	if routeExists(r, http.MethodGet, "/validate") {
		t.Fatal("public /validate should be off when PUBLIC_VALIDATE=false")
	}
}

func TestServiceListenerHasAdminAndInternalValidate(t *testing.T) {
	testutil.InitConfig(t, map[string]string{
		"public_self_service":    "true",
		"service_listener":       "true",
		"service_mtls":           "off",
		"mfa_encryption_key":     "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"superuser_email":        "root@example.com",
	})
	r, deps := testEngine(t)
	MountServiceListener(r, deps)

	if !routeExists(r, http.MethodGet, "/admin/api-keys") {
		t.Fatal("admin must be on service listener")
	}
	if !routeExists(r, http.MethodGet, "/validate") {
		t.Fatal("internal /validate must be on service listener")
	}
	// Kill switch off: login stays public-only, not duplicated on service.
	if routeExists(r, http.MethodPost, "/login") {
		t.Fatal("login should not be on service when public surface is on")
	}
}

func TestServiceListenerTakesUserSurfaceWhenKillSwitchOn(t *testing.T) {
	testutil.InitConfig(t, map[string]string{
		"public_self_service": "false",
		"service_listener":    "true",
		"service_mtls":        "off",
		"mfa_encryption_key":  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"superuser_email":     "root@example.com",
	})
	r, deps := testEngine(t)
	MountServiceListener(r, deps)

	if !routeExists(r, http.MethodPost, "/login") {
		t.Fatal("login must move to service when kill switch on")
	}
	if !routeExists(r, http.MethodGet, "/users/me") {
		t.Fatal("user protected routes must move to service when kill switch on")
	}
	if !routeExists(r, http.MethodGet, "/admin/api-keys") {
		t.Fatal("admin must remain on service")
	}
}

func TestSingleListenerCompatMountsAdminOnPublic(t *testing.T) {
	testutil.InitConfig(t, map[string]string{
		"public_self_service": "true",
		"service_listener":    "false",
		"mfa_encryption_key":  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"superuser_email":     "root@example.com",
	})
	r, deps := testEngine(t)
	MountPublicListener(r, deps)

	if !routeExists(r, http.MethodGet, "/admin/api-keys") {
		t.Fatal("single-listener compat must keep admin on the only listener")
	}
	if config.PublicValidateEnabled() && !routeExists(r, http.MethodGet, "/validate") {
		t.Fatal("expected public /validate in single-listener mode")
	}
}

func TestSurfaceMarker(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var got string
	r.Use(MarkSurface(SurfaceInternal))
	r.GET("/x", func(c *gin.Context) {
		v, _ := c.Get(ContextKeySurface)
		got, _ = v.(string)
		c.Status(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if got != SurfaceInternal {
		t.Fatalf("surface = %q", got)
	}
}
