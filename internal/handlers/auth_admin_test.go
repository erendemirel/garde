package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"garde/internal/middleware"
	"garde/internal/models"
	"garde/pkg/crypto"

	"github.com/gin-gonic/gin"
)

// Admin-object and validate endpoints through the same real-service stack.
func withAdmin(adminID string, super, admin bool) func(c *gin.Context) {
	return func(c *gin.Context) {
		c.Set("user_id", adminID)
		c.Set("is_superuser", super)
		c.Set("is_admin", admin)
	}
}

func TestValidateSessionHandlerTable(t *testing.T) {
	h, repo := newAuthTestStack(t)
	hash, err := crypto.HashPassword("DevAdminTest123!")
	if err != nil {
		t.Fatal(err)
	}
	u := &models.User{ID: "u-val", Email: "val@example.com", PasswordHash: hash, Status: models.UserStatusOk}
	if err := repo.StoreUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}

	// Login through the handler to mint a real session, then validate it.
	loginRec := serveAuth(t, h, http.MethodPost, "/login", withLogin("val@example.com", "DevAdminTest123!"), h.Login, nil)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login: %d", loginRec.Code)
	}
	cookie := loginRec.Header().Get("Set-Cookie")
	sessionID := strings.Split(strings.Split(cookie, "session=")[1], ";")[0]

	withSession := func(id string, viaHeader bool) func(c *gin.Context) {
		return func(c *gin.Context) {
			if viaHeader {
				c.Request.Header.Set("X-Session-ID", id)
			} else {
				q := c.Request.URL.Query()
				q.Set("session_id", id)
				c.Request.URL.RawQuery = q.Encode()
			}
		}
	}
	_ = withSession

	serveValidate := func(setup func(c *gin.Context)) *httptest.ResponseRecorder {
		gin.SetMode(gin.TestMode)
		router := gin.New()
		if setup != nil {
			router.Use(func(c *gin.Context) {
				setup(c)
				c.Next()
			})
		}
		router.GET("/validate", h.ValidateSession)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/validate", nil))
		return rec
	}

	if rec := serveValidate(nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing id: status = %d", rec.Code)
	}
	badSetup := func(c *gin.Context) { c.Request.Header.Set("X-Session-ID", "short") }
	if rec := serveValidate(badSetup); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed id: status = %d", rec.Code)
	}
	unknown := strings.Repeat("A", 86)
	unknownSetup := func(c *gin.Context) { c.Request.Header.Set("X-Session-ID", unknown) }
	if rec := serveValidate(unknownSetup); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown session: status = %d", rec.Code)
	}
	headerSetup := func(c *gin.Context) { c.Request.Header.Set("X-Session-ID", sessionID) }
	if rec := serveValidate(headerSetup); rec.Code != http.StatusOK {
		t.Fatalf("header validate: status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestAdminUserHandlersTable(t *testing.T) {
	h, repo := newAuthTestStack(t)
	seedHandlerUser(t, repo, "admin-au", "admin-au@example.com", "DevAdminTest123!")
	seedHandlerUser(t, repo, "target-au", "target-au@example.com", "DevAdminTest123!")

	t.Run("list users as superuser", func(t *testing.T) {
		rec := serveAuth(t, h, http.MethodGet, "/users", withAdmin("admin-au", true, false), h.ListUsers, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("list users without auth", func(t *testing.T) {
		rec := serveAuth(t, h, http.MethodGet, "/users", nil, h.ListUsers, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
	})
	t.Run("get user round trip", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("user_id", "admin-au")
			c.Set("is_superuser", true)
			c.Set("is_admin", false)
			c.Next()
		})
		router.GET("/users/:user_id", h.GetUser)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users/target-au", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users/ghost", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("unknown: status = %d", rec.Code)
		}
	})
	t.Run("delete self refused", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("user_id", "admin-au")
			c.Set("is_superuser", true)
			c.Set("is_admin", false)
			c.Next()
		})
		router.DELETE("/users/:user_id", h.DeleteUser)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/users/admin-au", nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("self delete: status = %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/users/target-au", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("delete: status = %d body = %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("request update guards", func(t *testing.T) {
		withReq := func(validated bool) func(c *gin.Context) {
			return func(c *gin.Context) {
				c.Set("user_id", "target-au")
				if validated {
					c.Set(middleware.ContextKeyValidatedRequest, models.RequestUpdateRequest{
						Updates: models.RequestUpdateFields{GroupsAdd: []string{"g"}},
					})
				}
			}
		}
		rec := serveAuth(t, h, http.MethodPost, "/req", withUserID(""), h.RequestUpdate, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("missing user: status = %d", rec.Code)
		}
		rec = serveAuth(t, h, http.MethodPost, "/req", withReq(false), h.RequestUpdate, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("missing validated: status = %d", rec.Code)
		}
		// Groups catalogue not loaded in unit tests: service error surfaces.
		rec = serveAuth(t, h, http.MethodPost, "/req", withReq(true), h.RequestUpdate, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("unloaded groups: status = %d", rec.Code)
		}
	})
}
