package repository

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	"garde/pkg/config"

	"github.com/lib/pq"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const (
	// One arbitrary but fixed key, so every replica starting at once serialises
	// on the same lock instead of racing to create the same tables.
	migrationAdvisoryLockID = 742015001

	// Conservative on purpose: garde is fronted by Redis for everything hot, so
	// the durable pool exists to serve account writes, not request volume.
	pgMaxOpenConns    = 10
	pgMaxIdleConns    = 5
	pgConnMaxLifetime = 30 * time.Minute
	pgConnMaxIdleTime = 5 * time.Minute

	pgConnectTimeout = 10 * time.Second
)

// OpenPostgres dials the durable store and verifies the connection before
// returning it. DATABASE_URL wins when set; otherwise the DSN is assembled
// from the individual POSTGRES_* secrets.
func OpenPostgres() (*sql.DB, error) {
	dsn, err := postgresDSN()
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	db.SetMaxOpenConns(pgMaxOpenConns)
	db.SetMaxIdleConns(pgMaxIdleConns)
	db.SetConnMaxLifetime(pgConnMaxLifetime)
	db.SetConnMaxIdleTime(pgConnMaxIdleTime)

	ctx, cancel := context.WithTimeout(context.Background(), pgConnectTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return db, nil
}

func postgresDSN() (string, error) {
	if dsn := strings.TrimSpace(config.Get("DATABASE_URL")); dsn != "" {
		return dsn, nil
	}

	host := strings.TrimSpace(config.Get("POSTGRES_HOST"))
	if host == "" {
		return "", errors.New("postgres is not configured: set DATABASE_URL or POSTGRES_HOST")
	}

	dbName := strings.TrimSpace(config.Get("POSTGRES_DB"))
	if dbName == "" {
		return "", errors.New("postgres is not configured: POSTGRES_DB is missing")
	}

	port := config.GetWithDefault("POSTGRES_PORT", "5432")
	sslMode := config.GetWithDefault("POSTGRES_SSLMODE", "disable")
	user := config.Get("POSTGRES_USER")
	password := config.Get("POSTGRES_PASSWORD")

	// url.URL rather than string concatenation: a password containing '@' or
	// '/' would otherwise silently produce a DSN pointing somewhere else.
	dsn := url.URL{
		Scheme:   "postgres",
		Host:     host + ":" + port,
		Path:     "/" + dbName,
		RawQuery: url.Values{"sslmode": []string{sslMode}}.Encode(),
	}
	if user != "" {
		if password != "" {
			dsn.User = url.UserPassword(user, password)
		} else {
			dsn.User = url.User(user)
		}
	}

	return dsn.String(), nil
}

// Migrate applies every embedded migration that has not run yet.
//
// The whole pass is held under a session-level advisory lock so that several
// instances booting together do not apply the same file concurrently; each
// file is then applied inside its own transaction alongside the
// schema_migrations row that records it, so a crash cannot leave a migration
// half-applied but marked done.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errPostgresUnavailable
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationAdvisoryLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		if _, err := conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", migrationAdvisoryLockID); err != nil {
			slog.Warn("Failed to release migration advisory lock", "error", err)
		}
	}()

	const ledger = `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`
	if _, err := conn.ExecContext(ctx, ledger); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	versions, err := migrationVersions()
	if err != nil {
		return err
	}

	for _, version := range versions {
		var applied bool
		if err := conn.QueryRowContext(ctx,
			"SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", version,
		).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", version, err)
		}
		if applied {
			continue
		}

		body, err := migrationFiles.ReadFile("migrations/" + version)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err)
		}

		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", version, err)
		}

		slog.Info("Applied database migration", "version", version)
	}

	return nil
}

func migrationVersions() ([]string, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations directory: %w", err)
	}

	versions := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		versions = append(versions, entry.Name())
	}
	// Filenames carry the ordering (001_, 002_, ...), so lexical sort is the
	// migration order.
	sort.Strings(versions)
	return versions, nil
}

// isUniqueViolation reports whether err is a Postgres unique-constraint
// failure (SQLSTATE 23505), which is how a duplicate email or a re-used id
// arrives from the driver.
func isUniqueViolation(err error) bool {
	if pqErr, ok := errors.AsType[*pq.Error](err); ok {
		return pqErr.Code == "23505"
	}
	return false
}
