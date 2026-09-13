package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// ValidateRequestParameters dispatches on FullPath. Exercise it end to end
// with real routes instead of calling the unexported validators directly.
func validationRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(ValidateRequestParameters())
	ok := func(c *gin.Context) {
		_, failed := c.Get(ContextKeyValidationFailed)
		if failed {
			c.Status(http.StatusTeapot)
			return
		}
		c.Status(http.StatusOK)
	}
	router.POST("/login", ok)
	router.POST("/users", ok)
	router.POST("/users/password/otp", ok)
	router.POST("/users/password/reset", ok)
	router.POST("/users/password/change", ok)
	router.POST("/users/mfa/setup", ok)
	router.POST("/users/mfa/verify", ok)
	router.POST("/users/mfa/disable", ok)
	router.POST("/sessions/revoke", ok)
	router.POST("/users/request-update-from-admin", ok)
	router.PUT("/users/:user_id", ok)
	router.GET("/health", ok)
	return router
}

func postJSON(t *testing.T, router *gin.Engine, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestValidationDispatchTable(t *testing.T) {
	router := validationRouter()
	cases := []struct {
		name string
		path string
		body string
		want int
	}{
		{"login valid", "/login", `{"email":"a@example.com","password":"DevAdminTest123!"}`, http.StatusOK},
		{"login bad email", "/login", `{"email":"nope","password":"DevAdminTest123!"}`, http.StatusBadRequest},
		{"login weak password", "/login", `{"email":"a@example.com","password":"weak"}`, http.StatusBadRequest},
		{"login empty body", "/login", ``, http.StatusBadRequest},
		{"register valid", "/users", `{"email":"a@example.com","password":"DevAdminTest123!"}`, http.StatusOK},
		{"register bad", "/users", `{"email":"a@example.com","password":"x"}`, http.StatusBadRequest},
		{"otp valid", "/users/password/otp", `{"email":"a@example.com"}`, http.StatusOK},
		{"otp bad email", "/users/password/otp", `{"email":"nope"}`, http.StatusBadRequest},
		{"disable mfa valid", "/users/mfa/disable", `{"mfa_code":"123456"}`, http.StatusOK},
		{"disable mfa bad code", "/users/mfa/disable", `{"mfa_code":"abc"}`, http.StatusBadRequest},
		{"mfa verify valid", "/users/mfa/verify", `{"code":"123456"}`, http.StatusOK},
		{"mfa verify bad email", "/users/mfa/verify", `{"email":"nope","code":"123456"}`, http.StatusBadRequest},
		{"mfa setup empty", "/users/mfa/setup", `{}`, http.StatusOK},
		{"password change valid", "/users/password/change", `{"old_password":"OldPassword1!","new_password":"NewPassword1!"}`, http.StatusOK},
		{"password change weak new", "/users/password/change", `{"old_password":"OldPassword1!","new_password":"x"}`, http.StatusBadRequest},
		{"password reset valid", "/users/password/reset", `{"email":"a@example.com","otp":"ABCD1234","new_password":"NewPassword1!"}`, http.StatusOK},
		{"password reset short otp", "/users/password/reset", `{"email":"a@example.com","otp":"ABC","new_password":"NewPassword1!"}`, http.StatusBadRequest},
		{"revoke valid", "/sessions/revoke", `{"user_id":"user-1"}`, http.StatusOK},
		{"revoke bad mfa", "/sessions/revoke", `{"user_id":"user-1","mfa_code":"xyz"}`, http.StatusBadRequest},
		{"request-update empty", "/users/request-update-from-admin", `{"updates":{}}`, http.StatusBadRequest},
		{"request-update with change", "/users/request-update-from-admin", `{"updates":{"permissions_add":["read"]}}`, http.StatusBadRequest}, // permissions system not loaded in tests
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := postJSON(t, router, tc.path, tc.body).Code; got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestValidationPutUserAndPassthrough(t *testing.T) {
	router := validationRouter()

	req := httptest.NewRequest(http.MethodPut, "/users/some-id", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty update: status = %d, want 400", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPut, "/users/some-id", strings.NewReader(`{"approve_update":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve update: status = %d, want 200", rec.Code)
	}

	// Unknown routes pass through untouched.
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("passthrough: status = %d, want 200", rec.Code)
	}

	// Bracket characters are rejected by Sanitize (validate-then-escape).
	req = httptest.NewRequest(http.MethodGet, "/health?q=hello<script>", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bracket query: status = %d, want 400", rec.Code)
	}

	// Overlong values exceed ValidateGenericInput's 1024 cap and are refused.
	req = httptest.NewRequest(http.MethodGet, "/health?q="+strings.Repeat("a", 2000), nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("overlong query: status = %d, want 400", rec.Code)
	}
}
