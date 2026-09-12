package crypto

import (
	"strings"
	"testing"
)

func TestGeneratePATRoundTrip(t *testing.T) {
	plaintext, id, hash, err := GeneratePAT()
	if err != nil {
		t.Fatalf("GeneratePAT: %v", err)
	}

	if !strings.HasPrefix(plaintext, "garde_pat_") {
		t.Fatalf("plaintext %q does not carry the garde_pat_ prefix", plaintext)
	}

	parsedID, secret, ok := ParsePAT(plaintext)
	if !ok {
		t.Fatalf("ParsePAT rejected a token we just minted: %q", plaintext)
	}
	if parsedID != id {
		t.Fatalf("parsed id = %q, want %q", parsedID, id)
	}
	if !APIKeySecretMatches(secret, hash) {
		t.Fatal("the secret half does not verify against the stored hash")
	}
}

func TestPATAndAPIKeyPrefixesAreIsolated(t *testing.T) {
	pat, _, _, err := GeneratePAT()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := ParseAPIKey(pat); ok {
		t.Fatal("ParseAPIKey must reject a PAT so /validate cannot accept it")
	}

	key, _, _, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := ParsePAT(key); ok {
		t.Fatal("ParsePAT must reject a tenant API key")
	}
}

func TestParsePATRejectsNonTokens(t *testing.T) {
	cases := []string{
		"",
		"garde_pat_",
		"garde_0011223344556677_secret",
		"garde_pat_short_secret",
		"garde_pat_zz11223344556677_secret",
	}
	for _, presented := range cases {
		if _, _, ok := ParsePAT(presented); ok {
			t.Errorf("ParsePAT(%q) accepted, want rejected", presented)
		}
	}
}
