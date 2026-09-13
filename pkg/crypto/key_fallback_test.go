package crypto_test

import (
	"testing"

	"garde/internal/testutil"
	"garde/pkg/crypto"
)

// Key preference: dedicated MFA_ENCRYPTION_KEY wins, API_KEY is the stable
// fallback, neither is a startup-blocking error.
func TestMFAEncryptionKeyPreference(t *testing.T) {
	testutil.InitConfig(t, map[string]string{
		"mfa_encryption_key": "dedicated-key",
		"api_key":            "TestApiKey123!TestApiKey123!",
	})
	withDedicated, err := crypto.MFAEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}

	testutil.InitConfig(t, map[string]string{"api_key": "TestApiKey123!TestApiKey123!"})
	withFallback, err := crypto.MFAEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(withDedicated) == string(withFallback) {
		t.Fatal("dedicated key ignored, fallback used while dedicated is set")
	}

	// Ciphertexts under different keys must not cross-decrypt.
	enc, err := crypto.EncryptString("secret")
	if err != nil {
		t.Fatal(err)
	}
	testutil.InitConfig(t, map[string]string{"mfa_encryption_key": "other-key"})
	if _, err := crypto.DecryptString(enc); err == nil {
		t.Fatal("ciphertext decrypts under a different key")
	}
}

func TestMFAEncryptionKeyUnavailable(t *testing.T) {
	testutil.InitConfig(t, map[string]string{})
	if _, err := crypto.MFAEncryptionKey(); err == nil {
		t.Fatal("expected error with no key material configured")
	}
	if _, err := crypto.EncryptString("x"); err == nil {
		t.Fatal("expected encrypt error with no key material")
	}
}
