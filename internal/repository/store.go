package repository

import (
	"context"
	"database/sql"
	"log/slog"
	"strconv"
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

// RedisRepository is an alias for Store kept for test helpers mid-migration; prefer Store.
type RedisRepository = Store

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

func NewRedisRepository() (*Store, error) { return NewStore() }

// NewRedisRepositoryFromClient wraps an existing Redis client for tests that
// only exercise ephemeral state (sessions, rate limits, OTPs). The durable
// half is absent, so user/PAT/API-key methods return errPostgresUnavailable;
// use NewStoreFromClients when those are needed.
func NewRedisRepositoryFromClient(client *redis.Client) *Store {
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

	s.client = redis.NewClient(&redis.Options{
		Addr:     s.host + ":" + s.port,
		Password: config.Get("REDIS_PASSWORD"),
		DB:       s.dbNum,
	})

	ctx, cancel := context.WithTimeout(context.Background(), redisOpTimeout)
	defer cancel()
	if err := s.client.Ping(ctx).Err(); err != nil {
		slog.Error("Redis connection error", "error", err)
		return err
	}

	slog.Info("Successfully connected to Redis", "host", s.host, "port", s.port)
	return nil
}

// Reconnect re-dials Redis with freshly rotated credentials. Postgres is left
// alone: database/sql re-reads nothing from config, and its pool recovers from
// dropped connections on its own.
func (s *Store) Reconnect() error {
	slog.Info("Redis: Reconnecting with new credentials")
	return s.connect()
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
