package config

import (
	"log/slog"
	"strings"
)

// Registration next-step labels returned on create (and always the same for a
// given config, including anti-enumeration fake successes).
const (
	RegistrationNextVerifyEmail = "verify_email"
	RegistrationNextAwaitAdmin  = "await_admin"
	RegistrationNextReady       = "ready"
)

// PublicSelfServiceEnabled is the public kill switch inverted: true means the
// public listener serves external auth (login, register, user self-service,
// optional public /validate). When false, the public listener keeps only
// probes + /public/config; auth moves to the service listener when enabled.
// Default true when unset.
func PublicSelfServiceEnabled() bool {
	raw := strings.TrimSpace(Get("PUBLIC_SELF_SERVICE"))
	if raw == "" {
		return true
	}
	return GetBool("PUBLIC_SELF_SERVICE")
}

// RequireAdminApproval reports whether new accounts must wait for admin
// approval. Default false when unset.
func RequireAdminApproval() bool {
	raw := strings.TrimSpace(Get("REQUIRE_ADMIN_APPROVAL"))
	if raw == "" {
		return false
	}
	return GetBool("REQUIRE_ADMIN_APPROVAL")
}

// rawEmailVerificationFlag is the configured verify setting before coercion.
// Default true when unset.
func rawEmailVerificationFlag() bool {
	raw := strings.TrimSpace(Get("REQUIRE_EMAIL_VERIFICATION"))
	if raw == "" {
		return true
	}
	return GetBool("REQUIRE_EMAIL_VERIFICATION")
}

// RequireEmailVerification reports whether new accounts must verify email.
// Default true when unset. When both admin approval and email verification
// would be off, email verification is forced on.
func RequireEmailVerification() bool {
	if !RequireAdminApproval() && !rawEmailVerificationFlag() {
		return true
	}
	return rawEmailVerificationFlag()
}

// EmailVerificationCoerced reports that email verification is on only because
// both registration gates were disabled.
func EmailVerificationCoerced() bool {
	return !RequireAdminApproval() && !rawEmailVerificationFlag()
}

// LogRegistrationGates emits effective gate settings (including coercion).
func LogRegistrationGates() {
	approval := RequireAdminApproval()
	verify := RequireEmailVerification()
	if EmailVerificationCoerced() {
		slog.Warn("REQUIRE_ADMIN_APPROVAL and REQUIRE_EMAIL_VERIFICATION are both off; enabling email verification")
	}
	slog.Info("Registration gates",
		"public_self_service", PublicSelfServiceEnabled(),
		"require_admin_approval", approval,
		"require_email_verification", verify,
		"email_verification_coerced", EmailVerificationCoerced(),
		"service_listener", ServiceListenerEnabled(),
	)
	if !PublicSelfServiceEnabled() && !ServiceListenerEnabled() {
		slog.Warn("PUBLIC_SELF_SERVICE is off and SERVICE_LISTENER is off — auth is unavailable on every listener")
	}
}

// RegistrationNextStep is the opaque post-register hint for clients.
func RegistrationNextStep() string {
	if RequireEmailVerification() {
		return RegistrationNextVerifyEmail
	}
	if RequireAdminApproval() {
		return RegistrationNextAwaitAdmin
	}
	return RegistrationNextReady
}
