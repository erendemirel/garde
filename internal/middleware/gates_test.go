package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// runGate wires a middleware in front of a 200 handler and returns the status.
func runGate(t *testing.T, mw gin.HandlerFunc, setup func(c *gin.Context)) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	if setup != nil {
		router.Use(func(c *gin.Context) {
			setup(c)
			c.Next()
		})
	}
	router.Use(mw)
	router.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	return rec.Code
}

func setFlags(super, admin bool) func(c *gin.Context) {
	return func(c *gin.Context) {
		c.Set("is_superuser", super)
		c.Set("is_admin", admin)
		c.Next()
	}
}

func TestAdminMiddlewareTable(t *testing.T) {
	cases := []struct {
		name  string
		setup func(c *gin.Context)
		want  int
	}{
		{"flags missing", nil, http.StatusUnauthorized},
		{"plain user", setFlags(false, false), http.StatusUnauthorized},
		{"admin", setFlags(false, true), http.StatusOK},
		{"superuser", setFlags(true, false), http.StatusOK},
		{"both", setFlags(true, true), http.StatusOK},
		{"wrong types", func(c *gin.Context) {
			c.Set("is_superuser", "yes")
			c.Set("is_admin", "yes")
			c.Next()
		}, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// AuthService is only read for flags via context; nil is safe here
			// because the middleware never dereferences it.
			if got := runGate(t, AdminMiddleware(nil), tc.setup); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSuperuserMiddlewareTable(t *testing.T) {
	cases := []struct {
		name  string
		setup func(c *gin.Context)
		want  int
	}{
		{"flag missing", nil, http.StatusUnauthorized},
		{"false", setFlags(false, true), http.StatusUnauthorized},
		{"true", setFlags(true, false), http.StatusOK},
		{"wrong type", func(c *gin.Context) {
			c.Set("is_superuser", 1)
			c.Next()
		}, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runGate(t, SuperuserMiddleware(), tc.setup); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRecoveryConvertsPanicToGeneric500(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(Recovery())
	router.GET("/boom", func(c *gin.Context) { panic("secret stack details") })
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if body := rec.Body.String(); body == "" || strings.Contains(body, "secret stack details") {
		t.Fatalf("panic leaked internals or empty body: %q", body)
	}
}

func TestRecoveryPassesThrough(t *testing.T) {
	if got := runGate(t, Recovery(), nil); got != http.StatusOK {
		t.Fatalf("status = %d, want 200", got)
	}
}
