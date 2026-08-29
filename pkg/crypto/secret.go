package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"garde/pkg/config"
)

const mfaKeyFallbackInfo = "garde-mfa-encryption-v1"

// MFAEncryptionKey returns a 32-byte AES key for MFA secret encryption.
// Preference order:
//  1. MFA_ENCRYPTION_KEY — raw string (hashed to 32 bytes) or base64-encoded 32 bytes
//  2. Derived from API_KEY (stable fallback so existing deployments keep working)
func MFAEncryptionKey() ([]byte, error) {
	if keyMaterial := strings.TrimSpace(config.Get("MFA_ENCRYPTION_KEY")); keyMaterial != "" {
		if decoded, err := base64.StdEncoding.DecodeString(keyMaterial); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
		sum := sha256.Sum256([]byte(keyMaterial))
		return sum[:], nil
	}

	apiKey := strings.TrimSpace(config.Get("API_KEY"))
	if apiKey == "" {
		return nil, fmt.Errorf("MFA encryption key unavailable: set MFA_ENCRYPTION_KEY or API_KEY")
	}
	sum := sha256.Sum256([]byte(mfaKeyFallbackInfo + ":" + apiKey))
	return sum[:], nil
}

// EncryptString encrypts plaintext with AES-256-GCM and returns a base64 payload.
func EncryptString(plaintext string) (string, error) {
	key, err := MFAEncryptionKey()
	if err != nil {
		return "", err
	}
	return encryptWithKey(key, []byte(plaintext))
}

// DecryptString decrypts a base64 AES-256-GCM payload produced by EncryptString.
func DecryptString(ciphertext string) (string, error) {
	key, err := MFAEncryptionKey()
	if err != nil {
		return "", err
	}
	plain, err := decryptWithKey(key, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func encryptWithKey(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func decryptWithKey(key []byte, encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plain, nil
}
