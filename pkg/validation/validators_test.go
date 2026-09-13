package validation

import (
	"strings"
	"testing"

	"garde/pkg/errors"

	"github.com/google/uuid"
)

func TestValidatePasswordTable(t *testing.T) {
	valid := []string{"DevAdminTest123!", "aB1!xxxx", strings.Repeat("aA1!", 16)}
	for _, pw := range valid {
		if err := ValidatePassword(pw); err != nil {
			t.Fatalf("ValidatePassword(%q) = %v, want nil", pw, err)
		}
	}
	invalid := []struct {
		name string
		pw   string
	}{
		{"too short", "aB1!"},
		{"too long", strings.Repeat("aA1!", 17)},
		{"no upper", "devadmintest123!"},
		{"no lower", "DEVADMINTEST123!"},
		{"no number", "DevAdminTest!!!"},
		{"no special", "DevAdminTest123"},
		{"angle brackets", "DevAdmin<123!"},
		{"braces", "DevAdmin{123!"},
		{"two spaces", "Dev Admin Test123!"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePassword(tc.pw); err == nil {
				t.Fatalf("ValidatePassword(%q) = nil, want error", tc.pw)
			}
		})
	}
}

func TestValidateEmailTable(t *testing.T) {
	for _, email := range []string{"user@example.com", "a.b+tag@sub.example.co"} {
		if err := ValidateEmail(email); err != nil {
			t.Fatalf("ValidateEmail(%q) = %v, want nil", email, err)
		}
	}
	for _, email := range []string{"", "no-at-sign", "@example.com", "user@", "user<>@example.com", strings.Repeat("a", 250) + "@example.com"} {
		if err := ValidateEmail(email); err == nil {
			t.Fatalf("ValidateEmail(%q) = nil, want error", email)
		}
	}
}

func TestValidateSessionIDLengths(t *testing.T) {
	if err := ValidateSessionID(strings.Repeat("A", 86)); err != nil {
		t.Fatalf("86-char id: %v", err)
	}
	for name, id := range map[string]string{
		"empty":   "",
		"short":   strings.Repeat("A", 85),
		"long":    strings.Repeat("A", 87),
		"padded":  strings.Repeat("A", 86) + "==",
		"legacy88": strings.Repeat("A", 88),
		"spaces":  strings.Repeat("A", 85) + " ",
		"plus":    strings.Repeat("A", 85) + "+",
		"slash":   strings.Repeat("A", 85) + "/",
		"angled":  strings.Repeat("A", 85) + "<",
		"equals":  strings.Repeat("A", 85) + "=",
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateSessionID(id); err == nil {
				t.Fatalf("ValidateSessionID(%q...) = nil, want error", id[:min(8, len(id))])
			}
		})
	}
}

func TestValidateMFACodeTable(t *testing.T) {
	if err := ValidateMFACode("123456"); err != nil {
		t.Fatalf("valid code: %v", err)
	}
	for name, code := range map[string]string{
		"empty": "", "short": "12345", "long": "1234567",
		"alpha": "abcdef", "alnum": "12345a", "spaces": "123 56",
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateMFACode(code); err == nil {
				t.Fatalf("ValidateMFACode(%q) = nil, want error", code)
			}
		})
	}
}

func TestValidateUserIDTable(t *testing.T) {
	if err := ValidateUserID(uuid.NewString()); err != nil {
		t.Fatalf("fresh uuid: %v", err)
	}
	for name, id := range map[string]string{
		"empty": "", "not uuid": "user-1", "numeric": "12345", "angled": "<uuid>",
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateUserID(id); err == nil {
				t.Fatalf("ValidateUserID(%q) = nil, want error", id)
			}
		})
	}
}

func TestValidatePermissionOrGroupNameTable(t *testing.T) {
	for _, name := range []string{"a", "read_users", "A1", strings.Repeat("a", MaxPermissionOrGroupNameLength)} {
		if err := ValidatePermissionOrGroupName(name); err != nil {
			t.Fatalf("ValidatePermissionOrGroupName(%q) = %v, want nil", name, err)
		}
	}
	for name, input := range map[string]string{
		"empty": "", "too long": strings.Repeat("a", MaxPermissionOrGroupNameLength+1),
		"hyphen": "read-users", "dot": "read.users", "space": "read users", "slash": "a/b",
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePermissionOrGroupName(input); err == nil {
				t.Fatalf("ValidatePermissionOrGroupName(%q) = nil, want error", input)
			}
		})
	}
}

func TestSanitizeStripsControlAndEscapesBrackets(t *testing.T) {
	got, err := Sanitize("hello\x00world")
	if err != nil {
		t.Fatal(err)
	}
	if got != "helloworld" {
		t.Fatalf("got %q want %q", got, "helloworld")
	}
	if err := ValidateGenericInput("hello <world>"); err == nil {
		t.Fatal("raw angle brackets pass ValidateGenericInput, want rejection")
	}
	// Validate-then-escape: brackets are refused, not turned into entities.
	if _, err := Sanitize("hello <world>"); err == nil {
		t.Fatal("Sanitize accepted angle brackets; ban list must run before HTML escape")
	}
	// Allowed text is still HTML-escaped after validation.
	escaped, err := Sanitize("hello & world")
	if err != nil {
		t.Fatalf("Sanitize amp: %v", err)
	}
	if escaped != "hello &amp; world" {
		t.Fatalf("got %q want HTML-escaped amp", escaped)
	}
}

func TestLoginOraclePairStaysDistinct(t *testing.T) {
	// The audit noted /login answers unknown vs locked accounts differently.
	// If these ever converge, the handler mapping must change with them.
	if errors.ErrAuthFailed == errors.ErrAccessRestricted {
		t.Fatal("oracle pair converged; update the login error mapping")
	}
}

func TestGenericInputLengthCap(t *testing.T) {
	if err := ValidateGenericInput(strings.Repeat("a", 1024)); err != nil {
		t.Fatalf("boundary length: %v", err)
	}
	if err := ValidateGenericInput(strings.Repeat("a", 1025)); err == nil {
		t.Fatal("overlong input accepted")
	}
	if _, err := Sanitize(strings.Repeat("a", 2000)); err == nil {
		t.Fatal("overlong sanitize accepted")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
