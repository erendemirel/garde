package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// UpdateUser binds raw JSON itself and serialises concurrent edits with a
// user lock; ListPermissions/Groups degrade without the catalogue.
func updateRouter(t *testing.T, h *AuthHandler, adminID string, super, admin bool) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", adminID)
		c.Set("is_superuser", super)
		c.Set("is_admin", admin)
		c.Next()
	})
	router.PUT("/users/:user_id", h.UpdateUser)
	return router
}

func putUser(t *testing.T, router *gin.Engine, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/users/"+target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestUpdateUserHandlerTable(t *testing.T) {
	h, repo := newAuthTestStack(t)
	seedHandlerUser(t, repo, "admin-uu", "admin-uu@example.com", "DevAdminTest123!")
	seedHandlerUser(t, repo, "target-uu", "target-uu@example.com", "DevAdminTest123!")
	ctx := context.Background()

	t.Run("missing user is 401", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.PUT("/users/:user_id", h.UpdateUser)
		rec := putUser(t, router, "target-uu", `{"approve_update":true}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("lock contention is 409", func(t *testing.T) {
		// Hold the lock outside the handler so its own acquire fails.
		if _, err := h.authService.AcquireUserLock(ctx, "target-uu", time.Hour); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = h.authService.ReleaseUserLock(ctx, "target-uu") })
		router := updateRouter(t, h, "admin-uu", true, false)
		rec := putUser(t, router, "target-uu", `{"approve_update":true}`)
		if rec.Code != http.StatusConflict {
			t.Fatalf("contended: status = %d body = %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("bad json is 400", func(t *testing.T) {
		router := updateRouter(t, h, "admin-uu", true, false)
		rec := putUser(t, router, "target-uu", `not json`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("unknown target is 404", func(t *testing.T) {
		router := updateRouter(t, h, "admin-uu", true, false)
		rec := putUser(t, router, "ghost", `{"approve_update":true}`)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("plain caller is 404", func(t *testing.T) {
		router := updateRouter(t, h, "admin-uu", false, false)
		rec := putUser(t, router, "target-uu", `{"approve_update":true}`)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("superuser status change is 200", func(t *testing.T) {
		router := updateRouter(t, h, "admin-uu", true, false)
		rec := putUser(t, router, "target-uu", `{"status":"locked by admin"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
		got, _ := repo.GetUserByID(ctx, "target-uu")
		if string(got.Status) != "locked by admin" {
			t.Fatalf("stored status = %q", got.Status)
		}
	})
}

func TestCatalogEmptyPaths(t *testing.T) {
	h, _ := newAuthTestStack(t)

	// No catalogue in unit tests: permissions endpoint reports it.
	rec := serveAuth(t, h, http.MethodGet, "/permissions", withUserID("u"), h.ListPermissions, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("permissions without catalogue: status = %d", rec.Code)
	}

	// Groups: unauthenticated is 401; authenticated returns the catalog (empty when unloaded).
	rec = serveAuth(t, h, http.MethodGet, "/groups", nil, h.ListGroups, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("groups without user: status = %d", rec.Code)
	}
	rec = serveAuth(t, h, http.MethodGet, "/groups", withUserID("u"), h.ListGroups, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("groups with user: status = %d", rec.Code)
	}
}
