package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"garde/pkg/config"

	"github.com/gin-gonic/gin"
)

func TestCookieCSRFMiddleware(t *testing.T) {
	initCORSSecrets(t, map[string]string{
		"cors_allow_origins": "http://localhost:5173",
		"cookie_same_site":   "lax",
	})

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextAuthMethod, AuthMethodCookie)
		c.Next()
	})
	router.Use(CookieCSRFMiddleware())
	router.POST("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	router.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	// Lax + missing Origin: allow
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("lax missing origin: %d", rec.Code)
	}

	// Bad Origin: reject
	req = httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad origin: %d", rec.Code)
	}

	// Good Origin: allow
	req = httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("good origin: %d", rec.Code)
	}

	// GET never checked
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d", rec.Code)
	}
}

func TestCookieCSRFMiddlewareSameSiteNoneRequiresOrigin(t *testing.T) {
	initCORSSecrets(t, map[string]string{
		"cors_allow_origins": "https://app.example.com",
		"cookie_same_site":   "none",
		"use_tls":            "true",
	})
	if config.GetCookieSameSite() != http.SameSiteNoneMode {
		t.Fatal("expected SameSite=None")
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextAuthMethod, AuthMethodCookie)
		c.Next()
	})
	router.Use(CookieCSRFMiddleware())
	router.POST("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("none missing origin: %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("none good origin: %d", rec.Code)
	}
}

func TestCookieCSRFSkipsBearer(t *testing.T) {
	initCORSSecrets(t, map[string]string{
		"cors_allow_origins": "http://localhost:5173",
		"cookie_same_site":   "none",
		"use_tls":            "true",
	})
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextAuthMethod, AuthMethodBearer)
		c.Next()
	})
	router.Use(CookieCSRFMiddleware())
	router.POST("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer without origin: %d", rec.Code)
	}
}
