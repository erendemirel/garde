package crypto

import (
	"encoding/base64"
	"testing"
)

func TestCipherErrorBranches(t *testing.T) {
	if _, err := encryptWithKey([]byte("short"), []byte("data")); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := decryptWithKey(make([]byte, 32), "!!!not-base64!!!"); err == nil {
		t.Fatal("bad base64 accepted")
	}
	key := make([]byte, 32)
	if _, err := decryptWithKey(key, base64.StdEncoding.EncodeToString([]byte("tiny"))); err == nil {
		t.Fatal("short ciphertext accepted")
	}
	enc, err := encryptWithKey(key, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	other := make([]byte, 32)
	other[0] = 1
	if _, err := decryptWithKey(other, enc); err == nil {
		t.Fatal("wrong key decrypts")
	}
	if compareSlices([]byte{1}, []byte{1, 2}) {
		t.Fatal("length mismatch compares true")
	}
	if !compareSlices([]byte{1, 2}, []byte{1, 2}) {
		t.Fatal("equal slices compare false")
	}
}
