package validation

import (
	"strings"
	"testing"
)

// Client ids reach the route table as a path segment, so anything needing
// escaping has to be refused rather than encoded around.
func TestAPIKeyLabelValidators(t *testing.T) {
	valid := []string{"acme", "acme-prod", "acme_prod", "acme.prod.eu", "A1", strings.Repeat("a", MaxAPIKeyNameLength)}
	invalid := []string{
		"",
		strings.Repeat("a", MaxAPIKeyNameLength+1),
		"acme prod",
		"acme/prod",
		"../etc",
		"acme:prod",
		"acme%2f",
		"acme\n",
	}

	for _, value := range valid {
		if err := ValidateAPIKeyName(value); err != nil {
			t.Fatalf("ValidateAPIKeyName(%q) = %v, want nil", value, err)
		}
		if err := ValidateAPIKeyClientID(value); err != nil {
			t.Fatalf("ValidateAPIKeyClientID(%q) = %v, want nil", value, err)
		}
	}

	for _, value := range invalid {
		if err := ValidateAPIKeyName(value); err == nil {
			t.Fatalf("ValidateAPIKeyName(%q) = nil, want an error", value)
		}
		if err := ValidateAPIKeyClientID(value); err == nil {
			t.Fatalf("ValidateAPIKeyClientID(%q) = nil, want an error", value)
		}
	}
}

// The two share a charset but not a message, since an operator needs to know
// which field they got wrong.
func TestAPIKeyLabelErrorsNameTheField(t *testing.T) {
	nameErr := ValidateAPIKeyName("")
	clientErr := ValidateAPIKeyClientID("")

	if nameErr == nil || clientErr == nil {
		t.Fatal("empty labels must be refused")
	}
	if nameErr.Error() == clientErr.Error() {
		t.Fatalf("both validators answer %q; the message should name the field", nameErr.Error())
	}
}
