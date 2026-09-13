package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// extractDomain reduces a CN to its last two DNS labels. Pin the behaviour
// here because MTLSMiddleware leans on it for the CN fallback path — see the
// audit note on sibling-subdomain acceptance.
func TestExtractDomainTable(t *testing.T) {
	cases := []struct {
		name string
		cn   string
		want string
	}{
		{"bare domain", "example.com", "example.com"},
		{"subdomain collapses", "api.example.com", "example.com"},
		{"deep subdomain collapses", "a.b.example.com", "example.com"},
		{"single label", "localhost", "localhost"},
		{"empty", "", ""},
		{"trailing dot keeps empty tail", "example.com.", "com."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractDomain(tc.cn); got != tc.want {
				t.Fatalf("extractDomain(%q) = %q, want %q", tc.cn, got, tc.want)
			}
		})
	}
}

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
