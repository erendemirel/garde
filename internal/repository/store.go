package repository

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"

	"garde/pkg/config"

	"github.com/go-redis/redis/v8"
)

// Store is garde's single storage facade over two backends with two different
// jobs.
//
// PostgreSQL is the durable authority: accounts, personal access tokens,
// tenant API keys, and the permission catalogue. It is the record that has to
// survive a restart and be correct under concurrent writes.
//
// Redis holds only ephemeral state — sessions, blacklists, rate-limit windows,
// OTPs, locks, audit trails. All of it is expiring by nature, so losing it
// costs a re-login rather than an account.
type Store struct {
	db     *sql.DB
	client *redis.Client
	host   string
	port   string
	dbNum  int
	mu     sync.RWMutex
}

// NewStore opens PostgreSQL, brings the schema up to date, and connects Redis.
func NewStore() (*Store, error) {
	db, err := OpenPostgres()
	if err != nil {
		return nil, err
	}

	if err := Migrate(context.Background(), db); err != nil {
		db.Close()
		return nil, err
	}
	slog.Info("Connected to PostgreSQL and applied migrations")

	dbNum, _ := strconv.Atoi(config.Get("REDIS_DB"))
	host := config.Get("REDIS_HOST")
	port := config.GetWithDefault("REDIS_PORT", "6379")

	store := &Store{
		db:    db,
		host:  host,
		port:  port,
		dbNum: dbNum,
	}

	if err := store.connect(); err != nil {
		db.Close()
		return nil, err
	}

	return store, nil
}

// NewStoreFromClients wires an already-built pair of backends, for tests that
// run against a throwaway database and an in-memory Redis.
func NewStoreFromClients(db *sql.DB, client *redis.Client) *Store {
	return &Store{db: db, client: client}
}

// NewStoreFromRedisClient wraps an existing Redis client for tests that only
// exercise ephemeral state (sessions, rate limits, OTPs). The durable half is
// absent, so user/PAT/API-key methods return errPostgresUnavailable; use
// NewStoreFromClients when those are needed.
func NewStoreFromRedisClient(client *redis.Client) *Store {
	return &Store{client: client}
}

// DB exposes the durable handle so the permission catalogue can share one pool
// rather than opening a second.
func (s *Store) DB() *sql.DB {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db
}

func (s *Store) connect() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client != nil {
		s.client.Close()
	}

	opts := redisClientOptions(s.host, s.port, s.dbNum)
	s.client = redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), redisOpTimeout)
	defer cancel()
	if err := s.client.Ping(ctx).Err(); err != nil {
		slog.Error("Redis connection error", "error", err)
		return err
	}

	slog.Info("Successfully connected to Redis",
		"host", s.host, "port", s.port, "tls", opts.TLSConfig != nil)
	return nil
}

// redisClientOptions builds go-redis options from the current secrets.
// TLS is off by default; set REDIS_TLS=true or REDIS_URL=rediss://… to enable.
func redisClientOptions(host, port string, dbNum int) *redis.Options {
	opts := &redis.Options{
		Addr:     net.JoinHostPort(host, port),
		Password: config.Get("REDIS_PASSWORD"),
		DB:       dbNum,
	}
	if redisTLSEnabled() {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host,
		}
	}
	return opts
}

func redisTLSEnabled() bool {
	if config.GetBool("REDIS_TLS") {
		return true
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(config.Get("REDIS_URL"))), "rediss://")
}

// Reconnect re-dials Redis and rebuilds the Postgres pool from the current
// secrets. database/sql does not pick up a rotated DSN/password on its own —
// connections in the old pool keep the credentials they were opened with.
func (s *Store) Reconnect() error {
	slog.Info("Reconnecting Redis and PostgreSQL after secret change")
	if err := s.connect(); err != nil {
		return err
	}
	return s.reconnectPostgres()
}

// reconnectPostgres opens a new pool from the current config and swaps it in.
// Ephemeral-only stores (tests with Redis alone) have no durable handle and
// are left alone.
func (s *Store) reconnectPostgres() error {
	s.mu.RLock()
	hadDB := s.db != nil
	s.mu.RUnlock()
	if !hadDB {
		return nil
	}

	newDB, err := OpenPostgres()
	if err != nil {
		return fmt.Errorf("reconnect postgres: %w", err)
	}

	s.mu.Lock()
	old := s.db
	if old == nil {
		s.mu.Unlock()
		_ = newDB.Close()
		return nil
	}
	s.db = newDB
	s.mu.Unlock()

	// Rebind before closing the old pool so catalogue queries never observe a
	// closed *sql.DB between swap and Close.
	if err := rebindPermissionRepository(newDB); err != nil {
		slog.Warn("Failed to rebind permission catalogue after postgres reconnect", "error", err)
	}

	if err := old.Close(); err != nil {
		slog.Warn("Failed to close previous PostgreSQL pool after reconnect", "error", err)
	}
	slog.Info("Reconnected to PostgreSQL")
	return nil
}

func (s *Store) getClient() *redis.Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.client
}

// database returns the durable handle, or an error when this Store was built
// for ephemeral-only use.
func (s *Store) database() (*sql.DB, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil, errPostgresUnavailable
	}
	return s.db, nil
}

// Ping checks both backends for health probes. A Store with no durable handle
// is ephemeral-only by construction, so there is nothing to probe there.
func (s *Store) Ping(ctx context.Context) error {
	if s.DB() != nil {
		if err := s.PingPostgres(ctx); err != nil {
			return err
		}
	}
	return s.PingRedis(ctx)
}

func (s *Store) PingRedis(ctx context.Context) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}
	return client.Ping(ctx).Err()
}

func (s *Store) PingPostgres(ctx context.Context) error {
	db, err := s.database()
	if err != nil {
		return err
	}
	return db.PingContext(ctx)
}

// Close shuts both backends down, reporting the first failure but always
// attempting each one.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error
	if s.client != nil {
		if err := s.client.Close(); err != nil {
			firstErr = err
		}
		s.client = nil
	}
	if s.db != nil {
		if err := s.db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.db = nil
	}
	return firstErr
}
