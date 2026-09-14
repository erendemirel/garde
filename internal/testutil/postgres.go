package testutil

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"garde/internal/repository"

	_ "github.com/lib/pq"
)

// TestDatabaseURLEnv is the scratch PostgreSQL DSN durable tests use.
// Point it at an empty/throwaway database — every NewTestStore truncates.
const TestDatabaseURLEnv = "GARDE_TEST_DATABASE_URL"

// OpenTestDB opens the scratch database, migrates it, and truncates tables.
// Skips the calling test when GARDE_TEST_DATABASE_URL is unset.
func OpenTestDB(t *testing.T) *sql.DB {
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
	if err := repository.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}

	const truncate = `TRUNCATE users, personal_access_tokens, tenant_api_keys,
		permission_visibility, permissions, groups RESTART IDENTITY CASCADE`
	if _, err := db.ExecContext(ctx, truncate); err != nil {
		t.Fatalf("reset test database: %v", err)
	}
	return db
}

// NewTestStore returns a Store backed by scratch Postgres + miniredis.
// Skips when GARDE_TEST_DATABASE_URL is unset.
//
// Do not call from garde/internal/repository tests — that creates an import
// cycle; use the package-local newDurableStore helper instead.
func NewTestStore(t *testing.T) *repository.Store {
	t.Helper()
	db := OpenTestDB(t)
	_, client := NewMiniRedis(t)
	return repository.NewStoreFromClients(db, client)
}
