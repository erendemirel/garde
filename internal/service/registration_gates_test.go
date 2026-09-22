package service

import (
	"context"
	"strings"
	"testing"

	"garde/internal/models"
	"garde/pkg/config"
	pkgerrors "garde/pkg/errors"
	"garde/pkg/mail"
)

func TestCreateUserInitialStatusMatrix(t *testing.T) {
	cases := []struct {
		name           string
		approval       string
		verify         string
		wantStatus     models.UserStatus
		wantNext       string
		expectVerifyMail bool
	}{
		{
			name:       "approval only (defaults)",
			approval:   "true",
			verify:     "false",
			wantStatus: models.UserStatusPendingApproval,
			wantNext:   config.RegistrationNextAwaitAdmin,
		},
		{
			name:             "verify only",
			approval:         "false",
			verify:           "true",
			wantStatus:       models.UserStatusEmailNotVerified,
			wantNext:         config.RegistrationNextVerifyEmail,
			expectVerifyMail: true,
		},
		{
			name:             "both on",
			approval:         "true",
			verify:           "true",
			wantStatus:       models.UserStatusEmailNotVerified,
			wantNext:         config.RegistrationNextVerifyEmail,
			expectVerifyMail: true,
		},
		{
			name:             "both off coerces verify",
			approval:         "false",
			verify:           "false",
			wantStatus:       models.UserStatusEmailNotVerified,
			wantNext:         config.RegistrationNextVerifyEmail,
			expectVerifyMail: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secrets := baseSecrets()
			secrets["require_admin_approval"] = tc.approval
			secrets["require_email_verification"] = tc.verify
			s := newFlowService(t, secrets)
			ctx := context.Background()

			var sent []string
			prev := mail.SendMailFunc
			t.Cleanup(func() { mail.SendMailFunc = prev })
			mail.SendMailFunc = func(to, subject, body string) error {
				sent = append(sent, subject+"|"+body)
				return nil
			}

			email := "new-" + strings.ReplaceAll(tc.name, " ", "-") + "@example.com"
			email = strings.Map(func(r rune) rune {
				if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '@' || r == '.' {
					return r
				}
				return -1
			}, strings.ToLower(email))
			resp, err := s.CreateUser(ctx, &models.CreateUserRequest{
				Email: email, Password: "DevAdminTest123!",
			})
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			if resp.Next != tc.wantNext {
				t.Fatalf("next = %q, want %q", resp.Next, tc.wantNext)
			}
			user, err := s.repo.GetUserByEmail(ctx, email)
			if err != nil {
				t.Fatal(err)
			}
			if user.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q", user.Status, tc.wantStatus)
			}
			if tc.expectVerifyMail {
				if len(sent) != 1 || !strings.Contains(sent[0], "Verify your email") {
					t.Fatalf("expected verify mail, got %#v", sent)
				}
			} else if len(sent) != 0 {
				t.Fatalf("unexpected mail: %#v", sent)
			}
		})
	}
}

func TestVerifyEmailAdvancesStatus(t *testing.T) {
	t.Run("verify then ok when approval off", func(t *testing.T) {
		secrets := baseSecrets()
		secrets["require_admin_approval"] = "false"
		secrets["require_email_verification"] = "true"
		s := newFlowService(t, secrets)
		ctx := context.Background()

		var body string
		prev := mail.SendMailFunc
		t.Cleanup(func() { mail.SendMailFunc = prev })
		mail.SendMailFunc = func(to, subject, b string) error {
			body = b
			return nil
		}

		email := "verify-ok@example.com"
		if _, err := s.CreateUser(ctx, &models.CreateUserRequest{Email: email, Password: "DevAdminTest123!"}); err != nil {
			t.Fatal(err)
		}
		token := extractVerifyToken(t, body)
		if err := s.VerifyEmail(ctx, email, token); err != nil {
			t.Fatal(err)
		}
		user, err := s.repo.GetUserByEmail(ctx, email)
		if err != nil {
			t.Fatal(err)
		}
		if user.Status != models.UserStatusOk {
			t.Fatalf("status = %q, want ok", user.Status)
		}
	})

	t.Run("verify then pending when both on", func(t *testing.T) {
		secrets := baseSecrets()
		secrets["require_admin_approval"] = "true"
		secrets["require_email_verification"] = "true"
		s := newFlowService(t, secrets)
		ctx := context.Background()

		var body string
		prev := mail.SendMailFunc
		t.Cleanup(func() { mail.SendMailFunc = prev })
		mail.SendMailFunc = func(to, subject, b string) error {
			body = b
			return nil
		}

		email := "verify-pending@example.com"
		if _, err := s.CreateUser(ctx, &models.CreateUserRequest{Email: email, Password: "DevAdminTest123!"}); err != nil {
			t.Fatal(err)
		}
		token := extractVerifyToken(t, body)
		if err := s.VerifyEmail(ctx, email, token); err != nil {
			t.Fatal(err)
		}
		user, err := s.repo.GetUserByEmail(ctx, email)
		if err != nil {
			t.Fatal(err)
		}
		if user.Status != models.UserStatusPendingApproval {
			t.Fatalf("status = %q, want pending", user.Status)
		}
	})

	t.Run("wrong token leaves unverified", func(t *testing.T) {
		secrets := baseSecrets()
		secrets["require_admin_approval"] = "false"
		secrets["require_email_verification"] = "true"
		s := newFlowService(t, secrets)
		ctx := context.Background()

		prev := mail.SendMailFunc
		t.Cleanup(func() { mail.SendMailFunc = prev })
		mail.SendMailFunc = func(to, subject, b string) error { return nil }

		email := "verify-bad@example.com"
		if _, err := s.CreateUser(ctx, &models.CreateUserRequest{Email: email, Password: "DevAdminTest123!"}); err != nil {
			t.Fatal(err)
		}
		if err := s.VerifyEmail(ctx, email, "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"); err != nil {
			t.Fatal(err)
		}
		user, err := s.repo.GetUserByEmail(ctx, email)
		if err != nil {
			t.Fatal(err)
		}
		if user.Status != models.UserStatusEmailNotVerified {
			t.Fatalf("status = %q, want email not verified", user.Status)
		}
	})
}

func TestUpdateUserCannotSkipEmailVerification(t *testing.T) {
	secrets := baseSecrets()
	secrets["require_admin_approval"] = "true"
	secrets["require_email_verification"] = "true"
	s := newFlowService(t, secrets)
	ctx := context.Background()

	prev := mail.SendMailFunc
	t.Cleanup(func() { mail.SendMailFunc = prev })
	mail.SendMailFunc = func(to, subject, b string) error { return nil }

	storeTestUser(t, s, "admin-1", "admin@example.com")

	email := "no-skip@example.com"
	resp, err := s.CreateUser(ctx, &models.CreateUserRequest{Email: email, Password: "DevAdminTest123!"})
	if err != nil {
		t.Fatal(err)
	}
	ok := models.UserStatusOk
	err = s.UpdateUser(ctx, "admin-1", resp.UserID, &models.UpdateUserRequest{Status: &ok}, true, false)
	if err == nil || err.Error() != pkgerrors.ErrEmailVerificationRequired {
		t.Fatalf("err = %v, want %q", err, pkgerrors.ErrEmailVerificationRequired)
	}
}

func TestLoginOpaqueForEmailNotVerified(t *testing.T) {
	secrets := baseSecrets()
	secrets["require_admin_approval"] = "false"
	secrets["require_email_verification"] = "true"
	s := newFlowService(t, secrets)
	ctx := context.Background()

	prev := mail.SendMailFunc
	t.Cleanup(func() { mail.SendMailFunc = prev })
	mail.SendMailFunc = func(to, subject, b string) error { return nil }

	email := "opaque-unverified@example.com"
	password := "DevAdminTest123!"
	if _, err := s.CreateUser(ctx, &models.CreateUserRequest{Email: email, Password: password}); err != nil {
		t.Fatal(err)
	}
	_, err := s.Login(ctx, &models.LoginRequest{Email: email, Password: password}, "10.0.0.1", "ua")
	if err == nil || err.Error() != pkgerrors.ErrAuthFailed {
		t.Fatalf("login err = %v, want opaque auth failed", err)
	}
}

func extractVerifyToken(t *testing.T, body string) string {
	t.Helper()
	const marker = "Your verification code is: "
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no token in mail body: %q", body)
	}
	tok := body[i+len(marker):]
	if j := strings.IndexAny(tok, "\r\n"); j >= 0 {
		tok = tok[:j]
	}
	tok = strings.TrimSpace(tok)
	if len(tok) != 32 {
		t.Fatalf("token %q len=%d, want 32", tok, len(tok))
	}
	return tok
}
