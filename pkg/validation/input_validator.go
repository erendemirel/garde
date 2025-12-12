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

func SanitizeInput(input string) string {

	input = strings.TrimSpace(input)

	// Remove control characters
	input = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, input)

	// Escape HTML special characters
	input = html.EscapeString(input)

	return input
}

// Check for common malicious patterns
func ValidateGenericInput(input string) error {
	if len(input) > maxInputLength {
		return fmt.Errorf("input exceeds maximum length of %d characters", maxInputLength)
	}

	if strings.ContainsAny(input, "<>{}[]") {
		return fmt.Errorf(errors.ErrDisallowedCharacters)
	}

	return nil
}

func Sanitize(input string) (string, error) {
	sanitized := SanitizeInput(input)

	if err := ValidateGenericInput(sanitized); err != nil {
		return "", err
	}

	return sanitized, nil
}

func ValidateSessionID(sessionID string) error {
	sanitized, err := Sanitize(sessionID)
	if err != nil {
		return fmt.Errorf(errors.ErrInvalidSessionID)
	}

	if len(sanitized) != 86 { // base64 encoded 64-byte session ID
		return fmt.Errorf(errors.ErrInvalidSessionID)
	}

	// Check if it's a valid base64 string
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
