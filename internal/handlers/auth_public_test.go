package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"garde/internal/middleware"
	"garde/internal/models"
	"garde/internal/repository"
	"garde/internal/service"
	"garde/internal/testutil"
	"garde/pkg/crypto"

	"github.com/gin-gonic/gin"
)

// Full-stack handler tests with a real service on miniredis. Validated
// requests are seeded the way ValidateRequestParameters would leave them.
func newAuthTestStack(t *testing.T) (*AuthHandler, *repository.Store) {
	t.Helper()
	testutil.InitConfig(t, map[string]string{
		"superuser_email":    "root@example.com",
		"mfa_encryption_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
	})
	repo := testutil.NewTestStore(t)
	return NewAuthHandler(service.NewAuthService(repo)), repo
}

func seedHandlerUser(t *testing.T, repo *repository.Store, id, email, password string) {
	t.Helper()
	hash, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	u := &models.User{ID: id, Email: email, PasswordHash: hash, Status: models.UserStatusOk}
	if err := repo.StoreUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
}

func serveAuth(t *testing.T, h *AuthHandler, method, path string, setup func(c *gin.Context), handler gin.HandlerFunc, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	if setup != nil {
		router.Use(func(c *gin.Context) {
			setup(c)
			c.Next()
		})
	}
	router.Handle(method, path, handler)
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func withLogin(email, password string) func(c *gin.Context) {
	return func(c *gin.Context) {
		c.Set(middleware.ContextKeyValidatedRequest, models.LoginRequest{Email: email, Password: password})
	}
}

func TestLoginHandlerTable(t *testing.T) {
	h, repo := newAuthTestStack(t)
	seedHandlerUser(t, repo, "u-login", "login@example.com", "DevAdminTest123!")

	t.Run("success sets cookie without body session", func(t *testing.T) {
		rec := serveAuth(t, h, http.MethodPost, "/login", withLogin("login@example.com", "DevAdminTest123!"), h.Login, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
		cookie := rec.Header().Get("Set-Cookie")
		if cookie == "" {
			t.Fatal("no Set-Cookie on login")
		}
		if !strings.Contains(cookie, "HttpOnly") {
			t.Fatalf("cookie missing HttpOnly: %q", cookie)
		}
		var parsed struct {
			Data struct {
				SessionID string `json:"session_id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.Data.SessionID != "" {
			t.Fatalf("session_id leaked in default login body: %q", parsed.Data.SessionID)
		}
	})

	t.Run("X-Return-Session includes body session", func(t *testing.T) {
		rec := serveAuth(t, h, http.MethodPost, "/login", func(c *gin.Context) {
			withLogin("login@example.com", "DevAdminTest123!")(c)
			c.Request.Header.Set("X-Return-Session", "true")
		}, h.Login, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
		var parsed struct {
			Data struct {
				SessionID string `json:"session_id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Data.SessionID) != 86 {
			t.Fatalf("session id len = %d", len(parsed.Data.SessionID))
		}
	})

	t.Run("wrong password is 401", func(t *testing.T) {
		rec := serveAuth(t, h, http.MethodPost, "/login", withLogin("login@example.com", "WrongPassword1!"), h.Login, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("missing validated request is 400", func(t *testing.T) {
		rec := serveAuth(t, h, http.MethodPost, "/login", nil, h.Login, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", rec.Code)
		}
	})
}

func TestLogoutHandlerTable(t *testing.T) {
	h, repo := newAuthTestStack(t)
	seedHandlerUser(t, repo, "u-logout", "logout@example.com", "DevAdminTest123!")

	login := func() string {
		rec := serveAuth(t, h, http.MethodPost, "/login", func(c *gin.Context) {
			withLogin("logout@example.com", "DevAdminTest123!")(c)
			c.Request.Header.Set("X-Return-Session", "true")
		}, h.Login, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("login status = %d", rec.Code)
		}
		var parsed struct {
			Data struct {
				SessionID string `json:"session_id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatal(err)
		}
		return parsed.Data.SessionID
	}

	t.Run("no session is 400", func(t *testing.T) {
		rec := serveAuth(t, h, http.MethodPost, "/logout", nil, h.Logout, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("cookie logout clears and kills", func(t *testing.T) {
		sessionID := login()
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.POST("/logout", h.Logout)
		req := httptest.NewRequest(http.MethodPost, "/logout", nil)
		req.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
		// Session dead afterwards: logging out again fails server-side.
		req2 := httptest.NewRequest(http.MethodPost, "/logout", nil)
		req2.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
		rec2 := httptest.NewRecorder()
		router.ServeHTTP(rec2, req2)
		if rec2.Code == http.StatusOK {
			t.Fatal("second logout with dead session still 200")
		}
	})
}

func TestRequestOTPHandlerIsSilent(t *testing.T) {
	h, _ := newAuthTestStack(t)
	withOTP := func(email string) func(c *gin.Context) {
		return func(c *gin.Context) {
			c.Set(middleware.ContextKeyValidatedRequest, models.RequestOTPRequest{Email: email})
		}
	}
	for _, email := range []string{"nobody@example.com", "also-nobody@example.com"} {
		rec := serveAuth(t, h, http.MethodPost, "/otp", withOTP(email), h.RequestOTP, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("email %q: status = %d", email, rec.Code)
		}
	}
	rec := serveAuth(t, h, http.MethodPost, "/otp", nil, h.RequestOTP, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing validated request: status = %d", rec.Code)
	}
}

func TestGetCurrentUserHandlerTable(t *testing.T) {
	h, repo := newAuthTestStack(t)
	seedHandlerUser(t, repo, "u-me", "me@example.com", "DevAdminTest123!")

	withUser := func(id string) func(c *gin.Context) {
		return func(c *gin.Context) {
			if id != "" {
				c.Set("user_id", id)
			}
		}
	}
	rec := serveAuth(t, h, http.MethodGet, "/me", withUser("u-me"), h.GetCurrentUser, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	rec = serveAuth(t, h, http.MethodGet, "/me", withUser(""), h.GetCurrentUser, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing user: status = %d", rec.Code)
	}
	rec = serveAuth(t, h, http.MethodGet, "/me", withUser("ghost"), h.GetCurrentUser, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown user: status = %d body = %s", rec.Code, rec.Body.String())
	}
	if got := errorMessage(t, rec); got == "" {
		t.Fatal("expected error message body")
	}
}
