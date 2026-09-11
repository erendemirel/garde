package crypto

import (
	"strings"
	"testing"
)

func TestGenerateAPIKeyRoundTrip(t *testing.T) {
	plaintext, id, hash, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	if !strings.HasPrefix(plaintext, "garde_") {
		t.Fatalf("plaintext %q does not carry the garde_ prefix", plaintext)
	}
	if strings.Contains(plaintext[len("garde_"):], hash) {
		t.Fatal("plaintext must not contain the stored hash")
	}

	parsedID, secret, ok := ParseAPIKey(plaintext)
	if !ok {
		t.Fatalf("ParseAPIKey rejected a key we just minted: %q", plaintext)
	}
	if parsedID != id {
		t.Fatalf("parsed id = %q, want %q", parsedID, id)
	}
	if !APIKeySecretMatches(secret, hash) {
		t.Fatal("the secret half does not verify against the stored hash")
	}
	if APIKeySecretMatches(secret+"x", hash) {
		t.Fatal("a modified secret verified against the stored hash")
	}
}

func TestGenerateAPIKeyIsUnique(t *testing.T) {
	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		_, id, _, err := GenerateAPIKey()
		if err != nil {
			t.Fatalf("GenerateAPIKey: %v", err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("id %q issued twice", id)
		}
		seen[id] = struct{}{}
	}
}

func TestParseAPIKeyRejectsNonKeys(t *testing.T) {
	// The legacy shared key must not parse, or the middleware would look it up
	// in Redis instead of comparing it against configuration.
	cases := map[string]string{
		"legacy shared secret":  "TestApiKey123!TestApiKey123!",
		"empty":                 "",
		"prefix only":           "garde_",
		"no secret half":        "garde_0011223344556677",
		"empty secret half":     "garde_0011223344556677_",
		"short id":              "garde_00112233_c2VjcmV0",
		"non-hex id":            "garde_zz11223344556677_c2VjcmV0",
		"uppercase hex id":      "garde_0011223344556677A_c2VjcmV0",
		"wrong prefix":          "other_0011223344556677_c2VjcmV0",
		"prefix without_suffix": "gardex0011223344556677_c2VjcmV0",
	}

	for name, presented := range cases {
		if _, _, ok := ParseAPIKey(presented); ok {
			t.Errorf("%s: ParseAPIKey(%q) accepted, want rejected", name, presented)
		}
	}
}

func TestParseAPIKeyKeepsSecretWithUnderscores(t *testing.T) {
	// base64url secrets contain '_', so only the first separator may split.
	presented := "garde_0011223344556677_abc_def_ghi"

	id, secret, ok := ParseAPIKey(presented)
	if !ok {
		t.Fatalf("ParseAPIKey(%q) rejected", presented)
	}
	if id != "0011223344556677" {
		t.Fatalf("id = %q", id)
	}
	if secret != "abc_def_ghi" {
		t.Fatalf("secret = %q, want the whole remainder", secret)
	}
}

func TestAPIKeySecretMatchesRejectsEmptyHash(t *testing.T) {
	// A record with no stored hash must never authenticate anyone.
	if APIKeySecretMatches("", "") {
		t.Fatal("empty secret matched an empty hash")
	}
	if APIKeySecretMatches("anything", "") {
		t.Fatal("a secret matched an empty hash")
	}
}
