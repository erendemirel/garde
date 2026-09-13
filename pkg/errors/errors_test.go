package errors

import (
	"testing"
)

// Sentinel catalogue: every message must be non-empty and unique. Handlers
// and clients may branch on these strings, so API-key vs PAT wording must
// stay distinct (token-prefixed PAT expiry hints).
func TestErrorMessagesNonEmptyAndUnique(t *testing.T) {
	seen := map[string]string{}
	add := func(name, msg string) {
		t.Helper()
		if msg == "" {
			t.Fatalf("%s is empty", name)
		}
		if prev, dup := seen[msg]; dup {
			t.Fatalf("message %q shared by %s and %s", msg, prev, name)
		}
		seen[msg] = name
	}

	add("ErrInvalidCredentials", ErrInvalidCredentials)
	add("ErrUnauthorized", ErrUnauthorized)
	add("ErrAccessRestricted", ErrAccessRestricted)
	add("ErrAuthFailed", ErrAuthFailed)
	add("ErrSessionInvalid", ErrSessionInvalid)
	add("ErrNoActiveSession", ErrNoActiveSession)
	add("ErrInvalidSessionID", ErrInvalidSessionID)
	add("ErrMFASetupFailed", ErrMFASetupFailed)
	add("ErrMFAVerificationFailed", ErrMFAVerificationFailed)
	add("ErrInvalidMFACode", ErrInvalidMFACode)
	add("ErrMFARequired", ErrMFARequired)
	add("ErrMFAAlreadyEnabled", ErrMFAAlreadyEnabled)
	add("ErrMFASetupRequired", ErrMFASetupRequired)
	add("ErrInvalidRequest", ErrInvalidRequest)
	add("ErrUserCreationFailed", ErrUserCreationFailed)
	add("ErrRequestTooLarge", ErrRequestTooLarge)
	add("ErrTooManyRequests", ErrTooManyRequests)
	add("ErrOperationFailed", ErrOperationFailed)
	add("ErrUserNotFound", ErrUserNotFound)
	add("ErrEmailAlreadyExists", ErrEmailAlreadyExists)
	add("ErrInvalidPermissionRequested", ErrInvalidPermissionRequested)
	add("ErrInvalidGroupRequested", ErrInvalidGroupRequested)
	add("ErrAPIKeyNotFound", ErrAPIKeyNotFound)
	add("ErrAPIKeyNotPermitted", ErrAPIKeyNotPermitted)
	add("ErrPATNotFound", ErrPATNotFound)
	add("ErrPATLimitReached", ErrPATLimitReached)
	add("ErrSessionRequired", ErrSessionRequired)
	add("ErrAdminScopeNotPermitted", ErrAdminScopeNotPermitted)
	add("ErrEmailLength", ErrEmailLength)
	add("ErrEmailFormat", ErrEmailFormat)
	add("ErrPasswordLength", ErrPasswordLength)
	add("ErrPasswordComplexity", ErrPasswordComplexity)
	add("ErrDisallowedCharacters", ErrDisallowedCharacters)
	add("ErrInvalidPermissionName", ErrInvalidPermissionName)
	add("ErrInvalidAPIKeyName", ErrInvalidAPIKeyName)
	add("ErrInvalidAPIKeyTenantID", ErrInvalidAPIKeyTenantID)
	add("ErrInvalidAPIKeyScope", ErrInvalidAPIKeyScope)
	add("ErrAPIKeyScopesRequired", ErrAPIKeyScopesRequired)
	add("ErrInvalidAPIKeyExpiry", ErrInvalidAPIKeyExpiry)
	add("ErrAPIKeyExpiryTooLong", ErrAPIKeyExpiryTooLong)
	add("ErrAPIKeyExpiryConflict", ErrAPIKeyExpiryConflict)
	add("ErrInvalidAPIKeyRateLimit", ErrInvalidAPIKeyRateLimit)
	add("ErrInvalidPATName", ErrInvalidPATName)
	add("ErrInvalidPATExpiry", ErrInvalidPATExpiry)
	add("ErrPATExpiryTooLong", ErrPATExpiryTooLong)
	add("ErrPATExpiryConflict", ErrPATExpiryConflict)
	add("ErrEmailSendFailed", ErrEmailSendFailed)
	add("ErrInvalidOTP", ErrInvalidOTP)
	add("ErrTooManyAttempts", ErrTooManyAttempts)
}
