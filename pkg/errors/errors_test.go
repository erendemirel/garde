package errors

import (
	"testing"
)

// Sentinel catalogue: every message must be non-empty. Messages must be
// unique with one intentional exception: the API-key and PAT expiry hints
// share wording (both name the same example duration). Handlers branch on
// these strings, so any new duplicate must be added to allowedDuplicates
// deliberately, never by accident.
func TestErrorMessagesNonEmptyAndUnique(t *testing.T) {
	allowedDuplicates := map[string]bool{
		"expires_in must be a positive duration such as 2160h": true,
		"expires_in and never_expires cannot both be set":      true,
	}
	// Tracks which allowlist entries actually fired: after the messages are
	// differentiated, the unused entries fail this test so the allowlist
	// gets removed instead of rotting.
	consumed := map[string]bool{}
	seen := map[string]string{}
	add := func(name, msg string) {
		t.Helper()
		if msg == "" {
			t.Fatalf("%s is empty", name)
		}
		if prev, dup := seen[msg]; dup && !allowedDuplicates[msg] {
			t.Fatalf("message %q shared by %s and %s", msg, prev, name)
		}
		if dup := seen[msg]; dup != "" {
			consumed[msg] = true
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

	for msg := range allowedDuplicates {
		if !consumed[msg] {
			t.Fatalf("allowlist entry %q no longer duplicated — the messages were differentiated, remove it", msg)
		}
	}
}
