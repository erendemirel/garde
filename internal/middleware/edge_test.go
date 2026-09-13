package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLimitBodySizeRejectsOversize(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(LimitBodySize(10))
	router.POST("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	body := strings.Repeat("a", 11)
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestLimitBodySizeAllowsSmall(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(LimitBodySize(1024))
	router.POST("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("hello"))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
