package config

import (
	"testing"
)

func TestPublicSelfServiceDefaultAndOverride(t *testing.T) {
	withSecrets(t, map[string]string{})
	if !PublicSelfServiceEnabled() {
		t.Fatal("unset PUBLIC_SELF_SERVICE should default to true")
	}

	withSecrets(t, map[string]string{"public_self_service": "false"})
	if PublicSelfServiceEnabled() {
		t.Fatal("PUBLIC_SELF_SERVICE=false should disable public surface")
	}
}

func TestRegistrationGatesDefaultsAndCoercion(t *testing.T) {
	// Defaults: approval off, email verify on.
	withSecrets(t, map[string]string{})
	if RequireAdminApproval() {
		t.Fatal("unset REQUIRE_ADMIN_APPROVAL should default to false")
	}
	if !RequireEmailVerification() {
		t.Fatal("unset REQUIRE_EMAIL_VERIFICATION should default to true")
	}
	if EmailVerificationCoerced() {
		t.Fatal("should not coerce when verify defaults on")
	}
	if got := RegistrationNextStep(); got != RegistrationNextVerifyEmail {
		t.Fatalf("next = %q, want %q", got, RegistrationNextVerifyEmail)
	}

	// Both explicitly off → coerce email verification on.
	withSecrets(t, map[string]string{
		"require_admin_approval":     "false",
		"require_email_verification": "false",
	})
	if !RequireEmailVerification() || !EmailVerificationCoerced() {
		t.Fatal("both-off should coerce email verification")
	}

	// Approval only.
	withSecrets(t, map[string]string{
		"require_admin_approval":     "true",
		"require_email_verification": "false",
	})
	if !RequireAdminApproval() || RequireEmailVerification() || EmailVerificationCoerced() {
		t.Fatal("approval-only flags wrong")
	}
	if got := RegistrationNextStep(); got != RegistrationNextAwaitAdmin {
		t.Fatalf("next = %q, want await_admin", got)
	}

	// Both on → verify first.
	withSecrets(t, map[string]string{
		"require_admin_approval":     "true",
		"require_email_verification": "true",
	})
	if got := RegistrationNextStep(); got != RegistrationNextVerifyEmail {
		t.Fatalf("next = %q, want verify first", got)
	}
}

func TestPublicValidateRespectsKillSwitch(t *testing.T) {
	withSecrets(t, map[string]string{
		"public_self_service": "false",
		"public_validate":     "true",
	})
	if PublicValidateEnabled() {
		t.Fatal("kill switch must force public /validate off even when PUBLIC_VALIDATE=true")
	}

	withSecrets(t, map[string]string{
		"public_self_service": "true",
		"service_listener":    "false",
	})
	if !PublicValidateEnabled() {
		t.Fatal("with kill switch off and no service listener, public /validate should be on")
	}
}
