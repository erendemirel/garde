package crypto_test

import (
	"os"
	"path/filepath"
	"testing"

	"garde/pkg/config"
	"garde/pkg/crypto"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "api_key"), []byte("TestApiKey123!TestApiKey123!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mfa_encryption_key"), []byte("dev-mfa-encryption-key-change-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}

	plain := "JBSWY3DPEHPK3PXP"
	enc, err := crypto.EncryptString(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if enc == plain {
		t.Fatal("ciphertext must differ from plaintext")
	}
	got, err := crypto.DecryptString(enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != plain {
		t.Fatalf("got %q, want %q", got, plain)
	}
}
