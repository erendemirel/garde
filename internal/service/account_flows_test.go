package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"garde/internal/models"
	"garde/internal/repository"
	"garde/internal/testutil"
	"garde/pkg/crypto"
	pkgerrors "garde/pkg/errors"
	"garde/pkg/mail"
	pkgsession "garde/pkg/session"

	"github.com/pquerna/otp/totp"
)

func newFlowService(t *testing.T, secrets map[string]string) *AuthService {
	t.Helper()
	testutil.InitConfig(t, secrets)
	return newAuthServiceWithMiniRedis(t)
}

func baseSecrets() map[string]string {
	return map[string]string{
		"superuser_email":            "root@example.com",
		"mfa_encryption_key":         "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		// Session self-service tests mint concurrent sessions from different IPs.
		"disable_multiple_ip_check":  "true",
	}
}

func TestNeedsMFASetupTable(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	storeTestUser(t, s, "enforced-1", "enforced@example.com")
	enforced, _ := s.repo.GetUserByID(ctx, "enforced-1")
	enforced.MFAEnforced = true
	if err := s.repo.StoreUser(ctx, enforced); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		id    string
		want  bool
		isErr bool
	}{
		{"enforced unenrolled", "enforced-1", true, false},
		{"by email too", "enforced@example.com", true, false},
		{"plain user", "helpdesk@example.com", false, false},
		{"unknown", "nobody", false, true},
	}
	// helpdesk user comes from storeTestUser helper id email pair below.
	storeTestUser(t, s, "plain-1", "helpdesk@example.com")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.NeedsMFASetup(ctx, tc.id)
			if tc.isErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestSetupVerifyDisableMFACycle(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	storeTestUser(t, s, "mfa-1", "mfa@example.com")

	// Not enforced: setup by ID is the authenticated path.
	resp, err := s.SetupMFA(ctx, "mfa-1")
	if err != nil || resp.Secret == "" || !strings.HasPrefix(resp.QRCodeURL, "data:image/") {
		t.Fatalf("setup = %+v, %v", resp, err)
	}

	if err := s.VerifyAndEnableMFA(ctx, "mfa-1", "000000"); err == nil || err.Error() != pkgerrors.ErrInvalidMFACode {
		t.Fatalf("wrong code err = %v, want %q", err, pkgerrors.ErrInvalidMFACode)
	}
	code, err := totp.GenerateCode(resp.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyAndEnableMFA(ctx, "mfa-1", code); err != nil {
		t.Fatalf("verify: %v", err)
	}
	user, _ := s.repo.GetUserByID(ctx, "mfa-1")
	if !user.MFAEnabled || user.MFASecret == "" {
		t.Fatal("user not marked enabled with secret")
	}
	// Temp secret consumed: verifying again fails.
	if err := s.VerifyAndEnableMFA(ctx, "mfa-1", code); err == nil {
		t.Fatal("second verify with consumed secret accepted")
	}
	if _, err := s.SetupMFA(ctx, "mfa-1"); err == nil || err.Error() != pkgerrors.ErrMFAAlreadyEnabled {
		t.Fatalf("re-setup err = %v, want %q", err, pkgerrors.ErrMFAAlreadyEnabled)
	}

	if err := s.DisableMFA(ctx, "mfa-1", "000000"); err == nil || err.Error() != pkgerrors.ErrInvalidMFACode {
		t.Fatalf("disable wrong code err = %v, want %q", err, pkgerrors.ErrInvalidMFACode)
	}
	code, err = totp.GenerateCode(user.MFASecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DisableMFA(ctx, "mfa-1", code); err != nil {
		t.Fatalf("disable: %v", err)
	}
	after, _ := s.repo.GetUserByID(ctx, "mfa-1")
	if after.MFAEnabled || after.MFASecret != "" {
		t.Fatal("MFA not fully cleared")
	}
}

func TestSetupMFAEnforcedByEmail(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	storeTestUser(t, s, "enf-1", "enf@example.com")
	u, _ := s.repo.GetUserByID(ctx, "enf-1")
	u.MFAEnforced = true
	if err := s.repo.StoreUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	// Enforced users may start setup unauthenticated, by email.
	if _, err := s.SetupMFA(ctx, "enf@example.com"); err != nil {
		t.Fatalf("enforced setup by email: %v", err)
	}
	if _, err := s.SetupMFA(ctx, "ghost@example.com"); err == nil {
		t.Fatal("setup for unknown user accepted")
	}
}

func TestDisableMFARefusedWhenEnforced(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	storeTestUser(t, s, "enf-2", "enf2@example.com")
	u, _ := s.repo.GetUserByID(ctx, "enf-2")
	u.MFAEnforced = true
	u.MFAEnabled = true
	u.MFASecret = "JBSWY3DPEHPK3PXP"
	if err := s.repo.StoreUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.DisableMFA(ctx, "enf-2", "123456"); err == nil || err.Error() != pkgerrors.ErrUnauthorized {
		t.Fatalf("err = %v, want %q", err, pkgerrors.ErrUnauthorized)
	}
}

func mockMail(t *testing.T) *[]string {
	t.Helper()
	var sent []string
	prev := mail.SendMailFunc
	t.Cleanup(func() { mail.SendMailFunc = prev })
	mail.SendMailFunc = func(to, subject, body string) error {
		sent = append(sent, to+"\n"+body)
		return nil
	}
	return &sent
}

func extractOTP(t *testing.T, captured string) string {
	t.Helper()
	const marker = "is: "
	i := strings.Index(captured, marker)
	if i < 0 {
		t.Fatalf("no OTP in mail: %q", captured)
	}
	otp := captured[i+len(marker):]
	if j := strings.Index(otp, "\n"); j >= 0 {
		otp = otp[:j]
	}
	if len(otp) != 8 {
		t.Fatalf("otp %q is not 8 chars", otp)
	}
	return otp
}

func TestSendOTPAndResetPasswordEndToEnd(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	hash, err := crypto.HashPassword("OldPassword1!")
	if err != nil {
		t.Fatal(err)
	}
	user := &models.User{ID: "otp-1", Email: "otp@example.com", PasswordHash: hash, Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	sent := mockMail(t)

	// Unknown emails and the superuser are silent no-ops (no oracle, no mail).
	if err := s.SendOTP(ctx, "nobody@example.com"); err != nil {
		t.Fatalf("unknown email: %v", err)
	}
	super := &models.User{ID: "root-1", Email: "root@example.com", Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, super); err != nil {
		t.Fatal(err)
	}
	if err := s.SendOTP(ctx, "root@example.com"); err != nil {
		t.Fatalf("superuser: %v", err)
	}
	if len(*sent) != 0 {
		t.Fatalf("mails sent for unknown/superuser: %d", len(*sent))
	}

	if err := s.SendOTP(ctx, "otp@example.com"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(*sent) != 1 {
		t.Fatalf("mails = %d, want 1", len(*sent))
	}
	otp := extractOTP(t, (*sent)[0])

	// Wrong code first: invalid, and the OTP is single-use afterwards.
	if err := s.ResetPassword(ctx, &models.PasswordResetRequest{
		Email: "otp@example.com", OTP: "ZZZZZZZZ", NewPassword: "NewPassword1!",
	}); err == nil || err.Error() != pkgerrors.ErrInvalidOTP {
		t.Fatalf("wrong otp err = %v, want %q", err, pkgerrors.ErrInvalidOTP)
	}

	if err := s.SendOTP(ctx, "otp@example.com"); err != nil {
		t.Fatal(err)
	}
	otp = extractOTP(t, (*sent)[1])
	if err := s.ResetPassword(ctx, &models.PasswordResetRequest{
		Email: "otp@example.com", OTP: otp, NewPassword: "OldPassword1!",
	}); err == nil || err.Error() != pkgerrors.ErrPasswordSameAsCurrent {
		t.Fatalf("same password err = %v, want %q", err, pkgerrors.ErrPasswordSameAsCurrent)
	}

	if err := s.SendOTP(ctx, "otp@example.com"); err != nil {
		t.Fatal(err)
	}
	otp = extractOTP(t, (*sent)[2])
	if err := s.ResetPassword(ctx, &models.PasswordResetRequest{
		Email: "otp@example.com", OTP: otp, NewPassword: "NewPassword1!",
	}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	// Old password dead, new password works.
	if _, err := s.Login(ctx, &models.LoginRequest{Email: "otp@example.com", Password: "OldPassword1!"}, "10.0.0.1", "ua"); err == nil {
		t.Fatal("old password still works after reset")
	}
	if _, err := s.Login(ctx, &models.LoginRequest{Email: "otp@example.com", Password: "NewPassword1!"}, "10.0.0.1", "ua"); err != nil {
		t.Fatalf("new password login: %v", err)
	}
	// Unknown email reset stays generic (no enumeration).
	if err := s.ResetPassword(ctx, &models.PasswordResetRequest{
		Email: "nobody@example.com", OTP: "ZZZZZZZZ", NewPassword: "NewPassword1!",
	}); err == nil || err.Error() != pkgerrors.ErrInvalidOTP {
		t.Fatalf("unknown email err = %v, want %q", err, pkgerrors.ErrInvalidOTP)
	}
}

func TestSendOTPRateLimited(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	hash, err := crypto.HashPassword("OldPassword1!")
	if err != nil {
		t.Fatal(err)
	}
	user := &models.User{ID: "otp-rl", Email: "otprl@example.com", PasswordHash: hash, Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	sent := mockMail(t)
	for i := 0; i < repository.OTPSendMax(); i++ {
		if err := s.SendOTP(ctx, "otprl@example.com"); err != nil {
			t.Fatalf("send %d: %v", i+1, err)
		}
	}
	if len(*sent) != repository.OTPSendMax() {
		t.Fatalf("mails = %d, want %d", len(*sent), repository.OTPSendMax())
	}
	if err := s.SendOTP(ctx, "otprl@example.com"); err != nil {
		t.Fatalf("over-limit send: %v", err)
	}
	if len(*sent) != repository.OTPSendMax() {
		t.Fatalf("over-limit still mailed: got %d", len(*sent))
	}
}

func TestChangePasswordRotates(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	hash, err := crypto.HashPassword("OldPassword1!")
	if err != nil {
		t.Fatal(err)
	}
	user := &models.User{ID: "cp-1", Email: "cp@example.com", PasswordHash: hash, Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	if err := s.ChangePassword(ctx, "cp-1", &models.ChangePasswordRequest{
		OldPassword: "WrongOld1!", NewPassword: "NewPassword1!",
	}); err == nil || err.Error() != pkgerrors.ErrInvalidCredentials {
		t.Fatalf("wrong old err = %v, want %q", err, pkgerrors.ErrInvalidCredentials)
	}
	if err := s.ChangePassword(ctx, "cp-1", &models.ChangePasswordRequest{
		OldPassword: "OldPassword1!", NewPassword: "OldPassword1!",
	}); err == nil || err.Error() != pkgerrors.ErrPasswordSameAsCurrent {
		t.Fatalf("same password err = %v, want %q", err, pkgerrors.ErrPasswordSameAsCurrent)
	}
	if err := s.ChangePassword(ctx, "cp-1", &models.ChangePasswordRequest{
		OldPassword: "OldPassword1!", NewPassword: "NewPassword1!",
	}); err != nil {
		t.Fatalf("change: %v", err)
	}
	if _, err := s.Login(ctx, &models.LoginRequest{Email: "cp@example.com", Password: "NewPassword1!"}, "10.0.0.1", "ua"); err != nil {
		t.Fatalf("login with new password: %v", err)
	}
	// Superuser password cannot rotate through this endpoint.
	super := &models.User{ID: "root-2", Email: "root@example.com", PasswordHash: hash, Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, super); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(ctx, "root-2", &models.ChangePasswordRequest{
		OldPassword: "OldPassword1!", NewPassword: "NewPassword1!",
	}); err == nil || err.Error() != pkgerrors.ErrUnauthorized {
		t.Fatalf("superuser err = %v, want %q", err, pkgerrors.ErrUnauthorized)
	}
}

func TestChangePasswordRevokesAllSessions(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	hash, err := crypto.HashPassword("OldPassword1!")
	if err != nil {
		t.Fatal(err)
	}
	user := &models.User{ID: "cp-sess", Email: "cpsess@example.com", PasswordHash: hash, Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	// Seed two live sessions directly (avoid multi-IP login heuristics).
	data := &pkgsession.SessionData{UserID: user.ID, IP: "h", UserAgent: "ua", CreatedAt: time.Now()}
	for _, id := range []string{"cp-sess-a", "cp-sess-b"} {
		if err := s.repo.StoreSessionData(ctx, id, data, time.Hour); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.ChangePassword(ctx, user.ID, &models.ChangePasswordRequest{
		OldPassword: "OldPassword1!", NewPassword: "NewPassword1!",
	}); err != nil {
		t.Fatalf("change: %v", err)
	}

	active, err := s.repo.GetUserActiveSessions(ctx, user.ID)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("active sessions after change = %v, want none", active)
	}
	for _, id := range []string{"cp-sess-a", "cp-sess-b"} {
		if _, err := s.repo.GetSessionData(ctx, id); err == nil {
			t.Fatalf("session %s still readable after password change", id)
		}
		banned, err := s.repo.IsSessionBlacklisted(ctx, id)
		if err != nil || !banned {
			t.Fatalf("session %s blacklist = %v, %v", id, banned, err)
		}
	}
}

func TestChangePasswordRevokesPATs(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	hash, err := crypto.HashPassword("OldPassword1!")
	if err != nil {
		t.Fatal(err)
	}
	user := &models.User{ID: "cp-pat", Email: "cppat@example.com", PasswordHash: hash, Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	pat := &models.PersonalAccessToken{
		ID: "patdeadbeef01", UserID: user.ID, Name: "ci",
		SecretHash: "hash", CreatedAt: now, ExpiresAt: nil,
	}
	if err := s.repo.StorePAT(ctx, pat); err != nil {
		t.Fatal(err)
	}

	if err := s.ChangePassword(ctx, user.ID, &models.ChangePasswordRequest{
		OldPassword: "OldPassword1!", NewPassword: "NewPassword1!",
	}); err != nil {
		t.Fatalf("change: %v", err)
	}
	got, err := s.repo.GetPAT(ctx, pat.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Revoked() {
		t.Fatal("PAT still usable after password change")
	}
}

func TestGetCurrentUserZeroGroupsHidesPermissions(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	user := &models.User{
		ID: "zg-1", Email: "zg@example.com", Status: models.UserStatusOk,
		Permissions: models.UserPermissions{"read": true, "write": true},
		Groups:      models.UserGroups{},
	}
	if err := s.repo.StoreUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCurrentUser(ctx, "zg-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Permissions) != 0 {
		t.Fatalf("zero-group permissions = %v, want empty", got.Permissions)
	}
}

func TestLoginClearsFailedLoginCounters(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	hash, err := crypto.HashPassword("OldPassword1!")
	if err != nil {
		t.Fatal(err)
	}
	user := &models.User{ID: "fl-1", Email: "fl@example.com", PasswordHash: hash, Status: models.UserStatusOk}
	if err := s.repo.StoreUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if _, err := s.repo.RecordFailedLogin(ctx, user.Email, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, &models.LoginRequest{Email: user.Email, Password: "OldPassword1!"}, "10.0.0.1", "ua"); err != nil {
		t.Fatalf("login: %v", err)
	}
	// A fresh failure after success should start at 1 again.
	n, err := s.repo.RecordFailedLogin(ctx, user.Email, "10.0.0.1")
	if err != nil || n != 1 {
		t.Fatalf("after clear, next failure n=%d err=%v, want 1", n, err)
	}
}

func TestGetCurrentUserAndListUsers(t *testing.T) {
	s := newFlowService(t, baseSecrets())
	ctx := context.Background()
	admin := storeTestUser(t, s, "admin-9", "admin9@example.com")
	storeTestUser(t, s, "user-9", "user9@example.com")

	got, err := s.GetCurrentUser(ctx, "user-9")
	if err != nil || got.Email != "user9@example.com" {
		t.Fatalf("me = %+v, %v", got, err)
	}
	if _, err := s.GetCurrentUser(ctx, "ghost"); err == nil {
		t.Fatal("unknown user returns nil error")
	}
	if _, err := s.ListUsers(ctx, "user-9", false, false); err == nil {
		t.Fatal("plain user lists users")
	}
	listed, err := s.ListUsers(ctx, admin.ID, true, false)
	if err != nil {
		t.Fatalf("superuser list: %v", err)
	}
	if len(listed) < 2 {
		t.Fatalf("listed = %d, want >= 2", len(listed))
	}
}
