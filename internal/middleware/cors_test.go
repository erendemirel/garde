package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"garde/pkg/config"

	"github.com/gin-gonic/gin"
)

func initCORSSecrets(t *testing.T, secrets map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, value := range secrets {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
}

func corsRequest(t *testing.T, method, origin string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(CORSMiddleware())
	router.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	router.POST("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	var req *http.Request
	if method == http.MethodOptions {
		req = httptest.NewRequest(http.MethodOptions, "/x", nil)
	} else if method == http.MethodPost {
		req = httptest.NewRequest(http.MethodPost, "/x", nil)
	} else {
		req = httptest.NewRequest(http.MethodGet, "/x", nil)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestCORSOriginAllowlistExact(t *testing.T) {
	initCORSSecrets(t, map[string]string{"cors_allow_origins": "http://localhost:5173, http://app.example.com "})

	rec := corsRequest(t, http.MethodGet, "http://localhost:5173")
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Fatalf("allowlisted origin not echoed: %q", got)
	}
	for _, origin := range []string{"http://evil.com", "http://localhost:5173.evil.com", ""} {
		rec := corsRequest(t, http.MethodGet, origin)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("origin %q echoed: %q", origin, got)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("origin %q: status = %d", origin, rec.Code)
		}
	}
}

func TestCORSPreflightAndHeaders(t *testing.T) {
	initCORSSecrets(t, map[string]string{"cors_allow_origins": "http://localhost:5173"})

	rec := corsRequest(t, http.MethodOptions, "http://localhost:5173")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}

	rec = corsRequest(t, http.MethodGet, "http://localhost:5173")
	for header, want := range map[string]string{
		"X-Frame-Options":                  "DENY",
		"X-Content-Type-Options":           "nosniff",
		"Content-Security-Policy":          "default-src 'self'",
		"Referrer-Policy":                  "strict-origin-when-cross-origin",
		"Permissions-Policy":               "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), midi=(), display-capture=(), accelerometer=(), gyroscope=(), magnetometer=()",
		"Access-Control-Allow-Credentials": "true",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("HSTS without TLS: %q", got)
	}

	initCORSSecrets(t, map[string]string{"cors_allow_origins": "http://localhost:5173", "use_tls": "true"})
	rec = corsRequest(t, http.MethodGet, "http://localhost:5173")
	if got := rec.Header().Get("Strict-Transport-Security"); got == "" {
		t.Fatal("HSTS missing with USE_TLS=true")
	}
}
