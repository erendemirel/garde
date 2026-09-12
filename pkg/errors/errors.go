package errors

// Authentication errors
const (
	ErrInvalidCredentials = "invalid credentials"
	ErrUnauthorized       = "unauthorized"
	ErrAccessRestricted   = "access temporarily restricted, please try again later"
	ErrAuthFailed         = "authentication failed, please try again"
)

// Session errors
const (
	ErrSessionInvalid   = "session invalid"
	ErrNoActiveSession  = "no active session"
	ErrInvalidSessionID = "invalid session ID"
)

// MFA errors
const (
	ErrMFASetupFailed        = "failed to setup MFA"
	ErrMFAVerificationFailed = "MFA verification failed"
	ErrInvalidMFACode        = "invalid MFA code"
	ErrMFARequired           = "MFA code required"
	ErrMFAAlreadyEnabled     = "MFA already enabled"
	ErrMFASetupRequired      = "MFA setup required"
)

// Request errors
const (
	ErrInvalidRequest     = "invalid request"
	ErrUserCreationFailed = "user creation failed"
	ErrRequestTooLarge    = "request body exceeds maximum allowed size"
	ErrTooManyRequests    = "too many requests"
	ErrHTTPRequestBodyTooLarge = "http: request body too large"
)

// Generic error message
const (
	ErrOperationFailed = "operation failed"
)

// User management errors
const (
	ErrUserNotFound               = "user not found"
	ErrEmailAlreadyExists         = "email already exists"
	ErrSuperUserInitFailed        = "failed to initialize superuser"
	ErrPermissionsNotLoaded       = "permissions system not loaded"
	ErrGroupsNotLoaded            = "groups system not loaded"
	ErrInvalidPermissionRequested = "invalid permission requested"
	ErrInvalidGroupRequested      = "invalid group requested"
	ErrCannotRemoveAllPermissions = "cannot approve update request that would remove all permissions"
	ErrCannotRemoveAllGroups      = "cannot approve update request that would remove all groups"
	ErrCannotAddGroupsNotIn       = "cannot approve adding groups you are not a member of"
)

// Service API key errors
//
// Nothing here distinguishes an unknown key from a wrong secret or a revoked
// one: authentication failures all answer with ErrUnauthorized. These are the
// two cases a caller is entitled to act on — the admin API reporting a key id
// it does not hold, and a holder of a valid key calling a route it was not
// issued for.
const (
	ErrAPIKeyNotFound     = "api key not found"
	ErrAPIKeyNotPermitted = "api key is not permitted for this endpoint"
	ErrPATNotFound        = "personal access token not found"
	ErrPATLimitReached    = "personal access token limit reached"
	ErrSessionRequired    = "a browser session is required to manage personal access tokens"
)

// Admin scope errors
//
// Anyone who reaches this is authenticated and is an admin; what they lack is
// the one scope the route declares. Saying so discloses nothing they could
// not already infer, and gives whoever is debugging the 403 something to act
// on — the same reasoning as ErrAPIKeyNotPermitted.
const (
	ErrAdminScopeNotPermitted = "admin account is not permitted for this endpoint"
)

// Input validation errors
const (
	ErrEmailLength            = "email is max 254 characters"
	ErrEmailFormat            = "invalid email format"
	ErrPasswordLength         = "password must be between 8 and 64 characters"
	ErrPasswordComplexity     = "password complexity requirements not met"
	ErrDisallowedCharacters  = "disallowed characters"
	ErrInvalidPermissionName  = "permission and group names must be 1-128 characters, alphanumeric and underscore only"
	ErrInvalidAPIKeyName      = "API key name must be 1-64 characters, alphanumeric with underscore, hyphen or dot"
	ErrInvalidAPIKeyTenantID  = "tenant_id must be 1-64 characters, alphanumeric with underscore, hyphen or dot"
	ErrInvalidAPIKeyScope     = "unknown API key scope"
	ErrAPIKeyScopesRequired   = "at least one scope must be listed; scopes are not granted by default"
	ErrInvalidAPIKeyExpiry    = "expires_in must be a positive duration such as 2160h"
	ErrAPIKeyExpiryTooLong    = "expires_in cannot exceed 8760h; pass never_expires to issue a key that does not expire"
	ErrAPIKeyExpiryConflict   = "expires_in and never_expires cannot both be set"
	ErrInvalidAPIKeyRateLimit = "rate_limit cannot be negative"
	ErrInvalidPATName         = "token name must be 1-64 characters, alphanumeric with underscore, hyphen or dot"
	ErrInvalidPATExpiry       = "expires_in must be a positive duration such as 2160h"
	ErrPATExpiryTooLong       = "expires_in cannot exceed 8760h; pass never_expires to issue a token that does not expire"
	ErrPATExpiryConflict      = "expires_in and never_expires cannot both be set"
)

// Mail errors
const (
	ErrEmailSendFailed = "failed to send mail"
)

// Account reset errors
const (
	ErrInvalidOTP      = "invalid or expired OTP"
	ErrTooManyAttempts = "too many unsuccessful attempts"
)
