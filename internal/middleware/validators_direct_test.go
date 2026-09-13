package middleware

import (
	"net/http/httptest"
	"testing"

	"garde/internal/models"

	"github.com/gin-gonic/gin"
)

func bareContext(t *testing.T, method, path string) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(method, path, nil)
	return c
}

// The dispatch test covers these through HTTP; here each rule is pinned
// directly, including the intentionally loose ones.
func TestMFARequestValidators(t *testing.T) {
	if err := validateMFARequest(&models.MFAVerifyRequest{Code: "123456"}); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if err := validateMFARequest(&models.MFAVerifyRequest{Email: "nope", Code: "123456"}); err == nil {
		t.Fatal("bad email accepted")
	}
	// Only sanitized, never format-checked at this layer (see audit note).
	if err := validateDisableMFARequest(&models.DisableMFARequest{MFACode: "anything-goes"}); err != nil {
		t.Fatalf("disable must only sanitize: %v", err)
	}
	if err := validateMFASetupRequest(&models.MFASetupRequest{}); err != nil {
		t.Fatalf("empty setup: %v", err)
	}
	if err := validateMFASetupRequest(&models.MFASetupRequest{Email: "nope"}); err == nil {
		t.Fatal("bad setup email accepted")
	}
}

func TestChangePasswordRequestValidator(t *testing.T) {
	good := &models.ChangePasswordRequest{OldPassword: "OldPassword1!", NewPassword: "NewPassword1!"}
	if err := validateChangePasswordRequest(good); err != nil {
		t.Fatalf("valid: %v", err)
	}
	badOld := &models.ChangePasswordRequest{OldPassword: "x", NewPassword: "NewPassword1!"}
	if err := validateChangePasswordRequest(badOld); err == nil {
		t.Fatal("weak old password accepted")
	}
	withBadMFA := &models.ChangePasswordRequest{OldPassword: "OldPassword1!", NewPassword: "NewPassword1!", MFACode: "abc"}
	if err := validateChangePasswordRequest(withBadMFA); err == nil {
		t.Fatal("malformed MFA code accepted")
	}
	withMFA := &models.ChangePasswordRequest{OldPassword: "OldPassword1!", NewPassword: "NewPassword1!", MFACode: "123456"}
	if err := validateChangePasswordRequest(withMFA); err != nil {
		t.Fatalf("valid MFA: %v", err)
	}
}

func TestPasswordResetRequestValidator(t *testing.T) {
	good := &models.PasswordResetRequest{Email: "a@example.com", OTP: "ABCD1234", NewPassword: "NewPassword1!"}
	if err := validatePasswordResetRequest(good); err != nil {
		t.Fatalf("valid: %v", err)
	}
	short := &models.PasswordResetRequest{Email: "a@example.com", OTP: "ABC", NewPassword: "NewPassword1!"}
	if err := validatePasswordResetRequest(short); err == nil {
		t.Fatal("short OTP accepted")
	}
	badEmail := &models.PasswordResetRequest{Email: "nope", OTP: "ABCD1234", NewPassword: "NewPassword1!"}
	if err := validatePasswordResetRequest(badEmail); err == nil {
		t.Fatal("bad email accepted")
	}
}

func TestRevokeSessionRequestValidator(t *testing.T) {
	good := &models.RevokeSessionRequest{UserID: "user-1"}
	if err := validateRevokeSessionRequest(good); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if good.UserID != "user-1" {
		t.Fatalf("user id rewritten to %q", good.UserID)
	}
	badMFA := &models.RevokeSessionRequest{UserID: "user-1", MFACode: "xyz"}
	if err := validateRevokeSessionRequest(badMFA); err == nil {
		t.Fatal("malformed MFA code accepted")
	}
}

func TestGetValidatedRequestRoundTrip(t *testing.T) {
	c := bareContext(t, "GET", "/x")
	want := models.LoginRequest{Email: "a@example.com", Password: "DevAdminTest123!"}
	c.Set(ContextKeyValidatedRequest, want)
	got, ok := GetValidatedRequest[models.LoginRequest](c)
	if !ok || got != want {
		t.Fatalf("got %+v, %v", got, ok)
	}
	if _, ok := GetValidatedRequest[models.CreateUserRequest](c); ok {
		t.Fatal("wrong type asserted successfully")
	}
	c2 := bareContext(t, "GET", "/x")
	if _, ok := GetValidatedRequest[models.LoginRequest](c2); ok {
		t.Fatal("missing key reports present")
	}
}
