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

// Input validation errors
const (
	ErrEmailLength          = "email is max 254 characters"
	ErrEmailFormat          = "invalid email format"
	ErrPasswordLength       = "password must be between 8 and 64 characters"
	ErrPasswordComplexity   = "password complexity requirements not met"
	ErrDisallowedCharacters = "disallowed characters"
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
