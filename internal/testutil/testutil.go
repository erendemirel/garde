// Package testutil gathers the shared conventions for backend unit tests.
//
// Convention (kept deliberately small):
//   - Table-driven tests, one behaviour per case, `t.Fatalf` with got/want.
//   - Config: seed the file-backed loader via InitConfig instead of
//     hand-rolling os.WriteFile + config.Init in every test.
//   - Redis: use NewMiniRedis (alicebob/miniredis) instead of a live server.
//     Callers wrap the client, e.g.
//     repository.NewRedisRepositoryFromClient(client).
//   - HTTP: gin.TestMode + httptest, assert status AND error message.
//   - No network dials, no sleeps for timing, restore any globals with
//     t.Cleanup.
//
// Existing tests predate this package and still hand-roll their setup;
// migrate them opportunistically, do not churn them in one go.
package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"garde/pkg/config"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
)

// MFAEncryptionKey is a fixed base64(32-byte) AES key for unit tests and local
// seed examples. Decode length must stay 32 — see crypto.ParseMFAEncryptionKey.
const MFAEncryptionKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

// MFAEncryptionKeyAlt is a second valid key for cross-decrypt tests.
const MFAEncryptionKeyAlt = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

// InitConfig seeds the file-backed config loader: each map entry becomes one
// file named after the (lowercase) key. Mirrors how Vault Agent renders
// /run/secrets (loader uppercases filenames on read).
func InitConfig(t *testing.T, secrets map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, value := range secrets {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
}

// NewMiniRedis starts an in-memory Redis and returns the server plus a client
// pointed at it. Both are closed automatically on test cleanup.
func NewMiniRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}
