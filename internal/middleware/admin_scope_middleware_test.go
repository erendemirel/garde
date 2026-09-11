package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"garde/pkg/config"

	"github.com/gin-gonic/gin"
)

// adminScopeRouter stands in for the chain AuthMiddleware and AdminMiddleware
// would have produced, so the gate can be tested on its own.
func adminScopeRouter(required string, seed func(*gin.Context)) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/users", func(c *gin.Context) {
		c.Set("user_id", "u-1")
		seed(c)
		c.Next()
	}, RequireAdminScope(required), func(c *gin.Context) {
		c.String(http.StatusOK, "reached")
	})
	return router
}

func callAdminRoute(t *testing.T, required string, seed func(*gin.Context)) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	adminScopeRouter(required, seed).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users", nil))
	return rec
}

func TestRequireAdminScopeDecisions(t *testing.T) {
	cases := []struct {
		name     string
		required string
		seed     func(*gin.Context)
		want     int
	}{
		{
			// Restricting the account that provisions admins would be theatre.
			name:     "superuser holds every scope even with no entry",
			required: config.ScopeAdminUsersDelete,
			seed: func(c *gin.Context) {
				c.Set("is_superuser", true)
				c.Set("is_admin", false)
			},
			want: http.StatusOK,
		},
		{
			name:     "admin with no restriction keeps the old bundle",
			required: config.ScopeAdminUsersDelete,
			seed: func(c *gin.Context) {
				c.Set("is_superuser", false)
				c.Set("is_admin", true)
				c.Set(contextAdminScopesEnforced, false)
			},
			want: http.StatusOK,
		},
		{
			name:     "admin holding the required scope passes",
			required: config.ScopeAdminUsersWrite,
			seed: func(c *gin.Context) {
				c.Set("is_superuser", false)
				c.Set("is_admin", true)
				c.Set(contextAdminScopesEnforced, true)
				c.Set(contextAdminScopes, []string{config.ScopeAdminUsersRead, config.ScopeAdminUsersWrite})
			},
			want: http.StatusOK,
		},
		{
			// The reason the feature exists: read and write without delete.
			name:     "admin lacking the required scope is refused",
			required: config.ScopeAdminUsersDelete,
			seed: func(c *gin.Context) {
				c.Set("is_superuser", false)
				c.Set("is_admin", true)
				c.Set(contextAdminScopesEnforced, true)
				c.Set(contextAdminScopes, []string{config.ScopeAdminUsersRead, config.ScopeAdminUsersWrite})
			},
			want: http.StatusForbidden,
		},
		{
			name:     "empty scope list denies",
			required: config.ScopeAdminUsersRead,
			seed: func(c *gin.Context) {
				c.Set("is_superuser", false)
				c.Set("is_admin", true)
				c.Set(contextAdminScopesEnforced, true)
				c.Set(contextAdminScopes, []string{})
			},
			want: http.StatusForbidden,
		},
		{
			// Reachable only by mounting the gate without AdminMiddleware.
			name:     "non-admin is refused even when enforcement is off",
			required: config.ScopeAdminUsersRead,
			seed: func(c *gin.Context) {
				c.Set("is_superuser", false)
				c.Set("is_admin", false)
			},
			want: http.StatusUnauthorized,
		},
		{
			// A context with nothing set at all must not read as permitted.
			name:     "absent flags are refused",
			required: config.ScopeAdminUsersRead,
			seed:     func(c *gin.Context) {},
			want:     http.StatusUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := callAdminRoute(t, tc.required, tc.seed).Code; got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

// The scope answers whether an operation is available, never which records it
// reaches, so it must not disturb the flag the handlers filter on.
func TestRequireAdminScopeLeavesIsAdminIntact(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	var seenAdmin bool
	router.GET("/users", func(c *gin.Context) {
		c.Set("user_id", "u-1")
		c.Set("is_superuser", false)
		c.Set("is_admin", true)
		c.Set(contextAdminScopesEnforced, true)
		c.Set(contextAdminScopes, []string{config.ScopeAdminUsersRead})
		c.Next()
	}, RequireAdminScope(config.ScopeAdminUsersRead), func(c *gin.Context) {
		seenAdmin = c.GetBool("is_admin")
		c.Status(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !seenAdmin {
		t.Fatal("is_admin did not survive the scope gate; handler filtering depends on it")
	}
}
