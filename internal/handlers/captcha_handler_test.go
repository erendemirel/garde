package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"garde/pkg/config"

	"github.com/gin-gonic/gin"
)

func initCaptchaSecrets(t *testing.T, secrets map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, value := range secrets {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatalf("write secret %s: %v", name, err)
		}
	}
	if err := config.Init(dir); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
}

func TestCaptchaHandlerConfigWhenEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initCaptchaSecrets(t, map[string]string{
		"cap_enabled":    "true",
		"cap_site_key":   "site-abc",
		"cap_secret_key": "sec-xyz-do-not-leak",
		"cap_api_url":    "http://cap:3000",
		"cap_public_url": "https://cap.example.com",
	})

	h := NewCaptchaHandler(nil)
	router := gin.New()
	router.GET("/captcha/config", h.GetConfig)
	router.GET("/admin/captcha", h.GetAdminStatus)

	t.Run("public config exposes widget endpoint without secret", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/captcha/config", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}

		var parsed struct {
			Data CaptchaConfigResponse `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatal(err)
		}
		if !parsed.Data.Enabled {
			t.Fatal("expected enabled")
		}
		if !parsed.Data.LoginProgressive || !parsed.Data.RegisterRequired {
			t.Fatalf("login_progressive=%v register_required=%v", parsed.Data.LoginProgressive, parsed.Data.RegisterRequired)
		}
		if parsed.Data.LoginRequired {
			t.Fatal("expected login_required false with no prior failures")
		}
		if parsed.Data.SiteKey != "site-abc" {
			t.Fatalf("site_key = %q", parsed.Data.SiteKey)
		}
		if parsed.Data.WidgetEndpoint != "https://cap.example.com/site-abc/" {
			t.Fatalf("widget_endpoint = %q", parsed.Data.WidgetEndpoint)
		}
		if parsed.Data.PublicURL != "https://cap.example.com" {
			t.Fatalf("public_url = %q", parsed.Data.PublicURL)
		}
		if strings.Contains(rec.Body.String(), "sec-xyz-do-not-leak") {
			t.Fatalf("public config leaked secret material: %s", rec.Body.String())
		}
	})

	t.Run("admin status reports secret configured", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/captcha", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}

		var parsed struct {
			Data CaptchaAdminStatusResponse `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			t.Fatal(err)
		}
		if !parsed.Data.Enabled || !parsed.Data.SecretConfigured {
			t.Fatalf("enabled=%v secret_configured=%v", parsed.Data.Enabled, parsed.Data.SecretConfigured)
		}
		if !parsed.Data.LoginProgressive || parsed.Data.LoginFailureThreshold != 1 {
			t.Fatalf("login_progressive=%v threshold=%d", parsed.Data.LoginProgressive, parsed.Data.LoginFailureThreshold)
		}
		if parsed.Data.APIURL != "http://cap:3000" {
			t.Fatalf("api_url = %q", parsed.Data.APIURL)
		}
		if parsed.Data.DashboardURL != "https://cap.example.com" {
			t.Fatalf("dashboard_url = %q", parsed.Data.DashboardURL)
		}
		if strings.Contains(rec.Body.String(), "sec-xyz-do-not-leak") {
			t.Fatal("admin status leaked cap_secret_key value")
		}
	})
}

func TestCaptchaHandlerConfigWhenDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initCaptchaSecrets(t, map[string]string{"cap_enabled": "false"})

	h := NewCaptchaHandler(nil)
	router := gin.New()
	router.GET("/captcha/config", h.GetConfig)

	req := httptest.NewRequest(http.MethodGet, "/captcha/config", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	var parsed struct {
		Data CaptchaConfigResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Data.Enabled {
		t.Fatal("expected disabled")
	}
	if parsed.Data.SiteKey != "" || parsed.Data.WidgetEndpoint != "" {
		t.Fatalf("disabled config should omit keys: %+v", parsed.Data)
	}
}
