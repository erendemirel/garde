package repository

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"garde/pkg/config"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
)

// TestDatabaseURLEnv matches testutil.TestDatabaseURLEnv (same scratch DSN).
const TestDatabaseURLEnv = "GARDE_TEST_DATABASE_URL"

// newTestDB opens the scratch database. Kept in-package (not via testutil)
// to avoid an import cycle: testutil.NewTestStore already imports repository.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := strings.TrimSpace(os.Getenv(TestDatabaseURLEnv))
	if dsn == "" {
		t.Skipf("%s is not set; skipping PostgreSQL-backed test", TestDatabaseURLEnv)
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping test database: %v", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}

	const truncate = `TRUNCATE users, personal_access_tokens, tenant_api_keys,
		permission_visibility, permissions, groups RESTART IDENTITY CASCADE`
	if _, err := db.ExecContext(ctx, truncate); err != nil {
		t.Fatalf("reset test database: %v", err)
	}

	return db
}

// newDurableStore is Postgres + miniredis (same shape as testutil.NewTestStore).
func newDurableStore(t *testing.T) *Store {
	t.Helper()
	db := newTestDB(t)
	return NewStoreFromClients(db, newMiniRedisClient(t))
}

func newMiniRedisClient(t *testing.T) *redis.Client {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// initTestConfig mirrors testutil.InitConfig without importing testutil
// (which would cycle through repository).
func initTestConfig(t *testing.T, secrets map[string]string) {
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
