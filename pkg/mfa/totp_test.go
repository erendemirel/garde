package mfa

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestGenerateSecretShape(t *testing.T) {
	key, err := GenerateSecret("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if key.Secret == "" {
		t.Fatal("secret is empty")
	}
	if !strings.Contains(key.URL, "garde") {
		t.Fatalf("URL %q does not mention issuer garde", key.URL)
	}
	if !strings.Contains(key.URL, "user%40example.com") && !strings.Contains(key.URL, "user@example.com") {
		t.Fatalf("URL %q does not mention the account", key.URL)
	}
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(key.QRCodeData, prefix) {
		t.Fatalf("QRCodeData has prefix %q, want %q", key.QRCodeData[:min(32, len(key.QRCodeData))], prefix)
	}
	if len(key.QRCodeData) <= len(prefix)+100 {
		t.Fatal("QR payload suspiciously short, PNG encode may have failed")
	}
}

func TestGenerateSecretUnique(t *testing.T) {
	a, err := GenerateSecret("same@example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateSecret("same@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if a.Secret == b.Secret {
		t.Fatal("two secrets for the same account are identical, RNG may be broken")
	}
}

func TestValidateCodeRoundTrip(t *testing.T) {
	key, err := GenerateSecret("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(key.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateCode(key.Secret, code) {
		t.Fatal("freshly generated code does not validate")
	}
}

func TestValidateCodeRejects(t *testing.T) {
	key, err := GenerateSecret("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(key.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Flip the last digit so the code is (almost surely) wrong.
	wrong := code[:5] + map[byte]string{'0': "1"}[code[5]]
	if wrong == code {
		wrong = code[:5] + "0"
	}
	if ValidateCode(key.Secret, wrong) {
		t.Fatal("tampered code validates")
	}
	if ValidateCode(key.Secret, "") {
		t.Fatal("empty code validates")
	}
	if ValidateCode("", code) {
		t.Fatal("empty secret validates")
	}
	if ValidateCode("not-a-secret!!", code) {
		t.Fatal("malformed secret validates")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
