package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Issued keys look like garde_<id>_<secret>.
//
// The id half is a public lookup handle: it is stored in clear, it is what
// logs and the admin API name a key by, and it is what makes verification a
// single Redis GET instead of a scan over every issued key. The secret half
// is 256 bits of randomness and is never persisted — only its SHA-256 is.
const (
	apiKeyPrefix      = "garde"
	apiKeyIDBytes     = 8
	apiKeySecretBytes = 32
)

// GenerateAPIKey mints a key. The plaintext is handed to the caller once, at
// creation; only id and secretHash are stored.
func GenerateAPIKey() (plaintext, id, secretHash string, err error) {
	idBytes := make([]byte, apiKeyIDBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return "", "", "", fmt.Errorf("failed to generate an API key id: %w", err)
	}

	secretBytes := make([]byte, apiKeySecretBytes)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", "", fmt.Errorf("failed to generate an API key secret: %w", err)
	}

	id = hex.EncodeToString(idBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)

	return apiKeyPrefix + "_" + id + "_" + secret, id, HashAPIKeySecret(secret), nil
}

// ParseAPIKey splits a presented credential into its lookup id and secret.
//
// ok is false for anything that is not shaped like one of our keys, which is
// how the middleware tells a per-tenant key apart from the legacy shared
// secret without a round trip to Redis.
func ParseAPIKey(presented string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(presented, apiKeyPrefix+"_")
	if !found {
		return "", "", false
	}

	id, secret, found = strings.Cut(rest, "_")
	if !found || secret == "" || len(id) != apiKeyIDBytes*2 {
		return "", "", false
	}
	for _, r := range id {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return "", "", false
		}
	}

	return id, secret, true
}

// HashAPIKeySecret is deliberately a plain SHA-256 and not a password hash.
//
// Slow key derivation exists to make guessing low-entropy human input
// expensive. The secret here is 256 random bits, so there is nothing to guess,
// and /validate would pay the derivation cost on every single request.
func HashAPIKeySecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// APIKeySecretMatches reports whether secret hashes to storedHash.
func APIKeySecretMatches(secret, storedHash string) bool {
	if storedHash == "" {
		return false
	}
	computed := HashAPIKeySecret(secret)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedHash)) == 1
}
