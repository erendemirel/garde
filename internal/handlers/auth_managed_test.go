package handlers

import (
	"context"
	"net/http"
	"testing"
	"time"

	"garde/internal/middleware"
	"garde/internal/models"
	"garde/pkg/crypto"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

func withUserID(id string) func(c *gin.Context) {
	return func(c *gin.Context) {
		if id != "" {
			c.Set("user_id", id)
		}
	}
}

func TestSetupMFAHandlerTable(t *testing.T) {
	h, repo := newAuthTestStack(t)
	seedHandlerUser(t, repo, "u-mfa", "mfa@example.com", "DevAdminTest123!")

	rec := serveAuth(t, h, http.MethodPost, "/setup", withUserID(""), h.SetupMFA, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing user: status = %d", rec.Code)
	}
	rec = serveAuth(t, h, http.MethodPost, "/setup", withUserID("u-mfa"), h.SetupMFA, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup: status = %d body = %s", rec.Code, rec.Body.String())
	}

	// Mark enabled: setup must now refuse.
	u, _ := repo.GetUserByID(context.Background(), "u-mfa")
	u.MFAEnabled = true
	if err := repo.StoreUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	rec = serveAuth(t, h, http.MethodPost, "/setup", withUserID("u-mfa"), h.SetupMFA, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("re-setup: status = %d", rec.Code)
	}
}

func TestVerifyAndDisableMFAHandlerCycle(t *testing.T) {
	h, repo := newAuthTestStack(t)
	seedHandlerUser(t, repo, "u-cycle", "cycle@example.com", "DevAdminTest123!")
	ctx := context.Background()

	const secret = "JBSWY3DPEHPK3PXP"
	if err := repo.StoreTempMFASecret(ctx, "u-cycle", secret); err != nil {
		t.Fatal(err)
	}
	withCode := func(code string, setValidated bool) func(c *gin.Context) {
		return func(c *gin.Context) {
			c.Set("user_id", "u-cycle")
			if setValidated {
				c.Set(middleware.ContextKeyValidatedRequest, models.MFAVerifyRequest{Code: code})
			}
		}
	}

	rec := serveAuth(t, h, http.MethodPost, "/verify", withUserID(""), h.VerifyAndEnableMFA, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing user: status = %d", rec.Code)
	}
	rec = serveAuth(t, h, http.MethodPost, "/verify", withCode("", true), h.VerifyAndEnableMFA, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty code: status = %d, want 400", rec.Code)
	}
	rec = serveAuth(t, h, http.MethodPost, "/verify", func(c *gin.Context) {
		c.Set("user_id", "u-cycle")
	}, h.VerifyAndEnableMFA, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing validated request: status = %d", rec.Code)
	}
	rec = serveAuth(t, h, http.MethodPost, "/verify", withCode("000000", true), h.VerifyAndEnableMFA, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong code: status = %d", rec.Code)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec = serveAuth(t, h, http.MethodPost, "/verify", withCode(code, true), h.VerifyAndEnableMFA, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d body = %s", rec.Code, rec.Body.String())
	}

	withDisable := func(code string) func(c *gin.Context) {
		return func(c *gin.Context) {
			c.Set("user_id", "u-cycle")
			c.Set(middleware.ContextKeyValidatedRequest, models.DisableMFARequest{MFACode: code})
		}
	}
	rec = serveAuth(t, h, http.MethodPost, "/disable", withDisable("000000"), h.DisableMFA, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("disable wrong code: status = %d", rec.Code)
	}
	u, _ := repo.GetUserByID(ctx, "u-cycle")
	code, err = totp.GenerateCode(u.MFASecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec = serveAuth(t, h, http.MethodPost, "/disable", withDisable(code), h.DisableMFA, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable: status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestDisableMFAHandlerRefusedWhenEnforced(t *testing.T) {
	h, repo := newAuthTestStack(t)
	seedHandlerUser(t, repo, "u-enf", "enf@example.com", "DevAdminTest123!")
	ctx := context.Background()
	u, _ := repo.GetUserByID(ctx, "u-enf")
	u.MFAEnforced = true
	u.MFAEnabled = true
	u.MFASecret = "JBSWY3DPEHPK3PXP"
	if err := repo.StoreUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	rec := serveAuth(t, h, http.MethodPost, "/disable", func(c *gin.Context) {
		c.Set("user_id", "u-enf")
		c.Set(middleware.ContextKeyValidatedRequest, models.DisableMFARequest{MFACode: "123456"})
	}, h.DisableMFA, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("enforced disable: status = %d", rec.Code)
	}
}

func TestCreateUserHandlerTable(t *testing.T) {
	h, _ := newAuthTestStack(t)
	withCreate := func(email, password string) func(c *gin.Context) {
		return func(c *gin.Context) {
			c.Set(middleware.ContextKeyValidatedRequest, models.CreateUserRequest{Email: email, Password: password})
		}
	}
	rec := serveAuth(t, h, http.MethodPost, "/users", nil, h.CreateUser, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing validated: status = %d", rec.Code)
	}
	rec = serveAuth(t, h, http.MethodPost, "/users", withCreate("newuser@example.com", "DevAdminTest123!"), h.CreateUser, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status = %d body = %s", rec.Code, rec.Body.String())
	}
	// Configured superuser email is forbidden, not created.
	rec = serveAuth(t, h, http.MethodPost, "/users", withCreate("root@example.com", "DevAdminTest123!"), h.CreateUser, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("superuser email: status = %d", rec.Code)
	}
}

func TestChangePasswordHandlerTable(t *testing.T) {
	h, repo := newAuthTestStack(t)
	seedHandlerUser(t, repo, "u-cp", "cp@example.com", "OldPassword1!")
	withChange := func(old, new string, validated bool) func(c *gin.Context) {
		return func(c *gin.Context) {
			c.Set("user_id", "u-cp")
			if validated {
				c.Set(middleware.ContextKeyValidatedRequest, models.ChangePasswordRequest{OldPassword: old, NewPassword: new})
			}
		}
	}
	rec := serveAuth(t, h, http.MethodPost, "/change", withUserID(""), h.ChangePassword, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing user: status = %d", rec.Code)
	}
	rec = serveAuth(t, h, http.MethodPost, "/change", withChange("", "", false), h.ChangePassword, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing validated: status = %d", rec.Code)
	}
	rec = serveAuth(t, h, http.MethodPost, "/change", withChange("WrongOld1!", "NewPassword1!", true), h.ChangePassword, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong old: status = %d", rec.Code)
	}
	rec = serveAuth(t, h, http.MethodPost, "/change", withChange("OldPassword1!", "NewPassword1!", true), h.ChangePassword, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("change: status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestResetPasswordHandlerTable(t *testing.T) {
	h, repo := newAuthTestStack(t)
	seedHandlerUser(t, repo, "u-rp", "rp@example.com", "OldPassword1!")
	ctx := context.Background()
	hash, err := crypto.HashPassword("ABCD1234")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.StoreOTP(ctx, "u-rp", hash); err != nil {
		t.Fatal(err)
	}
	withReset := func(email, otp string) func(c *gin.Context) {
		return func(c *gin.Context) {
			c.Set(middleware.ContextKeyValidatedRequest, models.PasswordResetRequest{
				Email: email, OTP: otp, NewPassword: "NewPassword1!",
			})
		}
	}
	rec := serveAuth(t, h, http.MethodPost, "/reset", nil, h.ResetPassword, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing validated: status = %d", rec.Code)
	}
	rec = serveAuth(t, h, http.MethodPost, "/reset", withReset("rp@example.com", "ZZZZZZZZ"), h.ResetPassword, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong otp: status = %d", rec.Code)
	}
	// Wrong attempt consumed the OTP; re-seed for the success path.
	if err := repo.StoreOTP(ctx, "u-rp", hash); err != nil {
		t.Fatal(err)
	}
	rec = serveAuth(t, h, http.MethodPost, "/reset", withReset("rp@example.com", "ABCD1234"), h.ResetPassword, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset: status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestRevokeUserSessionHandlerTable(t *testing.T) {
	h, repo := newAuthTestStack(t)
	seedHandlerUser(t, repo, "admin-rv", "admin-rv@example.com", "DevAdminTest123!")
	seedHandlerUser(t, repo, "target-rv", "target-rv@example.com", "DevAdminTest123!")

	withRevoke := func(adminID, target string, super, admin bool, validated bool) func(c *gin.Context) {
		return func(c *gin.Context) {
			if adminID != "" {
				c.Set("user_id", adminID)
			}
			c.Set("is_superuser", super)
			c.Set("is_admin", admin)
			if validated {
				c.Set(middleware.ContextKeyValidatedRequest, models.RevokeSessionRequest{UserID: target})
			}
		}
	}
	rec := serveAuth(t, h, http.MethodPost, "/revoke", withRevoke("", "target-rv", false, false, true), h.RevokeUserSession, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing user: status = %d", rec.Code)
	}
	rec = serveAuth(t, h, http.MethodPost, "/revoke", withRevoke("admin-rv", "target-rv", true, false, false), h.RevokeUserSession, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing validated: status = %d", rec.Code)
	}
	rec = serveAuth(t, h, http.MethodPost, "/revoke", withRevoke("admin-rv", "target-rv", true, false, true), h.RevokeUserSession, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("superuser revoke: status = %d body = %s", rec.Code, rec.Body.String())
	}
	rec = serveAuth(t, h, http.MethodPost, "/revoke", withRevoke("admin-rv", "target-rv", false, false, true), h.RevokeUserSession, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("plain revoke: status = %d", rec.Code)
	}
	rec = serveAuth(t, h, http.MethodPost, "/revoke", withRevoke("admin-rv", "ghost", true, false, true), h.RevokeUserSession, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown target: status = %d", rec.Code)
	}
}
