package repository

import "errors"

// Sentinels callers branch on. They live here rather than next to the queries
// that raise them because both the Postgres and the Redis halves of Store can
// produce them, and handlers match on them by identity.
var (
	ErrConcurrentUpdate   = errors.New("concurrent update detected")
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrPATNotFound        = errors.New("personal access token not found")
	ErrAPIKeyNotFound     = errors.New("api key not found")

	ErrPermissionAlreadyExists = errors.New("permission already exists")
	ErrGroupAlreadyExists      = errors.New("group already exists")
	ErrVisibilityAlreadyExists = errors.New("permission visibility mapping already exists")
)

var (
	errRedisClientUnavailable = errors.New("redis client not initialized")
	errPostgresUnavailable    = errors.New("postgres connection not initialized")
	errUserNotFound           = errors.New("user not found")
)
