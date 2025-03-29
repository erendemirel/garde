package crypto

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/argon2"
)

type PasswordConfig struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

var defaultConfig = &PasswordConfig{
	time:    3,
	memory:  64 * 1024,
	threads: 4,
	keyLen:  32,
}

func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		defaultConfig.time,
		defaultConfig.memory,
		defaultConfig.threads,
		defaultConfig.keyLen,
	)

	combined := append(salt, hash...)
	encoded := base64.StdEncoding.EncodeToString(combined)
	return encoded, nil
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	decoded, err := base64.StdEncoding.DecodeString(encodedHash)
	if err != nil {
		return false, err
	}

	salt := decoded[:16]
	storedHash := decoded[16:]

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		defaultConfig.time,
		defaultConfig.memory,
		defaultConfig.threads,
		defaultConfig.keyLen,
	)

	match := compareSlices(hash, storedHash)
	return match, nil
}

// Constant-time comparison of two byte slices
func compareSlices(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
