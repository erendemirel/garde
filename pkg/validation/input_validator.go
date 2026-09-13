package validation

import (
	"fmt"
	"html"
	"regexp"
	"strings"
	"unicode"

	"garde/pkg/errors"

	"github.com/google/uuid"
)

const (
	MinPasswordLength   = 8
	MaxPasswordLength   = 64
	MaxEmailLength      = 254  // RFC 5321
	MaxConsecutiveChars = 3    // Maximum consecutive same characters
	MaxWhitespace       = 1    // Maximum consecutive whitespace characters
	maxInputLength      = 1024 // General max length for inputs
)

var (
	// RFC 5322 compliant email regex
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_\x60{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
)

type PasswordError struct {
	TooShort      bool
	TooLong       bool
	NoUpper       bool
	NoLower       bool
	NoNumber      bool
	NoSpecial     bool
	CommonPattern bool
}

func (e PasswordError) HasErrors() bool {
	return e.TooShort || e.TooLong || e.NoUpper || e.NoLower ||
		e.NoNumber || e.NoSpecial || e.CommonPattern
}

func ValidatePassword(password string) error {
	password = strings.TrimSpace(password)

	// Remove control characters
	password = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, password)

	// Check for disallowed characters
	if strings.ContainsAny(password, "<>{}[]") {
		return fmt.Errorf(errors.ErrDisallowedCharacters)
	}

	if len(password) < MinPasswordLength || len(password) > MaxPasswordLength {
		return fmt.Errorf(errors.ErrPasswordLength)
	}

	if strings.Count(password, " ") > MaxWhitespace {
		return fmt.Errorf(errors.ErrDisallowedCharacters)
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return fmt.Errorf(errors.ErrPasswordComplexity)
	}

	return nil
}

func ValidateEmail(email string) error {
	sanitized, err := Sanitize(email)
	if err != nil {
		return err
	}

	if len(sanitized) > MaxEmailLength {
		return fmt.Errorf(errors.ErrEmailLength)
	}
	if !emailRegex.MatchString(sanitized) {
		return fmt.Errorf(errors.ErrEmailFormat)
	}
	return nil
}

// NormalizeEmail lowercases and trims for stable storage and role comparisons.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// cleanInput trims whitespace and strips control characters without HTML-escaping,
// so ban-list checks still see the caller's real brackets.
func cleanInput(input string) string {
	input = strings.TrimSpace(input)
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, input)
}

func SanitizeInput(input string) string {
	return html.EscapeString(cleanInput(input))
}

// Check for common malicious patterns (on unescaped text).
func ValidateGenericInput(input string) error {
	if len(input) > maxInputLength {
		return fmt.Errorf("input exceeds maximum length of %d characters", maxInputLength)
	}

	if strings.ContainsAny(input, "<>{}[]") {
		return fmt.Errorf(errors.ErrDisallowedCharacters)
	}

	return nil
}

// Sanitize cleans, validates banned characters, then HTML-escapes.
// Validate-then-escape keeps the <>{}[] ban meaningful; escaping first
// turned every bracket into an entity and made ValidateGenericInput dead.
func Sanitize(input string) (string, error) {
	cleaned := cleanInput(input)

	if err := ValidateGenericInput(cleaned); err != nil {
		return "", err
	}

	return html.EscapeString(cleaned), nil
}

func ValidateSessionID(sessionID string) error {
	sanitized, err := Sanitize(sessionID)
	if err != nil {
		return fmt.Errorf(errors.ErrInvalidSessionID)
	}

	// RawURLEncoding of 64 bytes = 86 chars, no padding.
	if len(sanitized) != 86 {
		return fmt.Errorf(errors.ErrInvalidSessionID)
	}

	for _, r := range sanitized {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '-' && r != '_' {
			return fmt.Errorf(errors.ErrInvalidSessionID)
		}
	}

	return nil
}

func ValidateMFACode(code string) error {
	sanitized, err := Sanitize(code)
	if err != nil {
		return err
	}

	if len(sanitized) != 6 {
		return fmt.Errorf(errors.ErrInvalidMFACode)
	}

	for _, r := range sanitized {
		if !unicode.IsDigit(r) {
			return fmt.Errorf(errors.ErrInvalidMFACode)
		}
	}

	return nil
}

func ValidateUserID(id string) error {
	sanitized, err := Sanitize(id)
	if err != nil {
		return err
	}

	// UUID format validation
	if _, err := uuid.Parse(sanitized); err != nil {
		return fmt.Errorf(errors.ErrInvalidRequest)
	}

	return nil
}

const MaxPermissionOrGroupNameLength = 128

func ValidatePermissionOrGroupName(name string) error {
	if name == "" || len(name) > MaxPermissionOrGroupNameLength {
		return fmt.Errorf(errors.ErrInvalidPermissionName)
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return fmt.Errorf(errors.ErrInvalidPermissionName)
		}
	}
	return nil
}

const MaxAPIKeyNameLength = 64

// API key names identify the caller in logs and in the admin listing, so they
// allow the hyphens and dots that service and tenant names normally carry.
func ValidateAPIKeyName(name string) error {
	if !isAPIKeyLabel(name) {
		return fmt.Errorf(errors.ErrInvalidAPIKeyName)
	}
	return nil
}

// Tenant ids take the same shape as names but answer a different question:
// the name labels one key, the tenant id names the holder of several. It is
// also a path segment on the revoke-by-tenant route, so the charset has to
// stay free of anything that would need escaping.
func ValidateAPIKeyTenantID(tenantID string) error {
	if !isAPIKeyLabel(tenantID) {
		return fmt.Errorf(errors.ErrInvalidAPIKeyTenantID)
	}
	return nil
}

func ValidatePATName(name string) error {
	if !isAPIKeyLabel(name) {
		return fmt.Errorf(errors.ErrInvalidPATName)
	}
	return nil
}

func isAPIKeyLabel(value string) bool {
	if value == "" || len(value) > MaxAPIKeyNameLength {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}
