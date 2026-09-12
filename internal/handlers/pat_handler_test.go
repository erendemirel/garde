package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"garde/internal/models"
	"garde/internal/repository"
	pkgerrors "garde/pkg/errors"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

func newPATTestHandler(t *testing.T) *PATHandler {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewPATHandler(repository.NewRedisRepositoryFromClient(client))
}

func patRouter(h *PATHandler, withSession bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", "user-1")
		if withSession {
			c.Set("session_id", "sess-1")
		}
		c.Next()
	})
	router.POST("/users/me/tokens", h.CreatePAT)
	router.GET("/users/me/tokens", h.ListPATs)
	router.DELETE("/users/me/tokens/:token_id", h.RevokePAT)
	return router
}

func TestCreatePATRequiresSession(t *testing.T) {
	router := patRouter(newPATTestHandler(t), false)
	body, _ := json.Marshal(map[string]any{"name": "ci"})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/users/me/tokens", bytes.NewReader(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := errorMessage(t, rec); got != pkgerrors.ErrSessionRequired {
		t.Fatalf("message = %q, want %q", got, pkgerrors.ErrSessionRequired)
	}
}

func TestCreateListRevokePAT(t *testing.T) {
	h := newPATTestHandler(t)
	router := patRouter(h, true)

	body, _ := json.Marshal(map[string]any{"name": "ci"})
	req := httptest.NewRequest(http.MethodPost, "/users/me/tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", rec.Code, rec.Body.String())
	}

	var created struct {
		Data models.CreatePATResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Data.Token == "" || created.Data.ID == "" {
		t.Fatalf("missing token fields: %+v", created.Data)
	}
	if created.Data.ExpiresAt == nil {
		t.Fatal("default expiry missing")
	}
	if remaining := time.Until(*created.Data.ExpiresAt); remaining > models.DefaultPATTLL+time.Minute {
		t.Fatalf("expiry too far: %v", remaining)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users/me/tokens", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	var listed struct {
		Data models.ListPATsResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed.Data.Total != 1 || listed.Data.Tokens[0].ID != created.Data.ID {
		t.Fatalf("list = %+v", listed.Data)
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/users/me/tokens/"+created.Data.ID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users/me/tokens", nil))
	_ = json.Unmarshal(rec.Body.Bytes(), &listed)
	if listed.Data.Total != 0 {
		t.Fatalf("revoked token still listed: %+v", listed.Data)
	}
}

func TestCreatePATNeverExpires(t *testing.T) {
	router := patRouter(newPATTestHandler(t), true)
	body, _ := json.Marshal(map[string]any{"name": "forever", "never_expires": true})
	req := httptest.NewRequest(http.MethodPost, "/users/me/tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data models.CreatePATResponse `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Data.ExpiresAt != nil {
		t.Fatal("never_expires should omit expiry")
	}
}
