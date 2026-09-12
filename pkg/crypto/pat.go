package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Personal access tokens look like garde_pat_<id>_<secret>.
//
// The prefix is deliberately not parseable by ParseAPIKey: a PAT must never
// authenticate as a tenant key on /validate. Same id/secret layout otherwise,
// so verification stays a single Redis GET against a SHA-256 hash.
const patPrefix = "garde_pat"

// GeneratePAT mints a personal access token. Plaintext is returned once;
// only id and secretHash are stored.
func GeneratePAT() (plaintext, id, secretHash string, err error) {
	idBytes := make([]byte, apiKeyIDBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return "", "", "", fmt.Errorf("failed to generate a PAT id: %w", err)
	}

	secretBytes := make([]byte, apiKeySecretBytes)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", "", fmt.Errorf("failed to generate a PAT secret: %w", err)
	}

	id = hex.EncodeToString(idBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)

	return patPrefix + "_" + id + "_" + secret, id, HashAPIKeySecret(secret), nil
}

// ParsePAT splits a presented PAT into its lookup id and secret.
//
// ok is false for anything that is not shaped like a PAT — including tenant
// API keys and the legacy shared secret.
func ParsePAT(presented string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(presented, patPrefix+"_")
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
