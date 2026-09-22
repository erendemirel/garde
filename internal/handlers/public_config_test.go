package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"garde/internal/testutil"
	"garde/pkg/config"

	"github.com/gin-gonic/gin"
)

func TestGetPublicConfig(t *testing.T) {
	testutil.InitConfig(t, map[string]string{
		"public_self_service":        "false",
		"require_admin_approval":     "false",
		"require_email_verification": "true",
	})
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/public/config", GetPublicConfig)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/public/config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var wrap struct {
		Data PublicConfigResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &wrap); err != nil {
		t.Fatal(err)
	}
	if wrap.Data.PublicSelfService {
		t.Fatal("expected public_self_service false")
	}
	if wrap.Data.RequireAdminApproval {
		t.Fatal("expected admin approval false")
	}
	if !wrap.Data.RequireEmailVerification {
		t.Fatal("expected email verification true")
	}
	if wrap.Data.RegistrationNext != config.RegistrationNextVerifyEmail {
		t.Fatalf("next = %q", wrap.Data.RegistrationNext)
	}
}
