package crypto_test

import (
	"testing"

	"garde/internal/testutil"
	"garde/pkg/crypto"
)

func TestMFAEncryptionKeyRequiresDedicatedSecret(t *testing.T) {
	testutil.InitConfig(t, map[string]string{
		"mfa_encryption_key": "dedicated-key",
		"api_key":            "TestApiKey123!TestApiKey123!",
	})
	got, err := crypto.MFAEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 {
		t.Fatalf("key len = %d, want 32", len(got))
	}

	// API_KEY alone must never unlock MFA encryption.
	testutil.InitConfig(t, map[string]string{"api_key": "TestApiKey123!TestApiKey123!"})
	if _, err := crypto.MFAEncryptionKey(); err == nil {
		t.Fatal("expected error when only API_KEY is set")
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

func TestMFAEncryptionKeysDoNotCrossDecrypt(t *testing.T) {
	testutil.InitConfig(t, map[string]string{"mfa_encryption_key": "key-a"})
	enc, err := crypto.EncryptString("secret")
	if err != nil {
		t.Fatal(err)
	}
	testutil.InitConfig(t, map[string]string{"mfa_encryption_key": "key-b"})
	if _, err := crypto.DecryptString(enc); err == nil {
		t.Fatal("ciphertext decrypts under a different key")
	}
}
