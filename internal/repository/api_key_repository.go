package repository

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"garde/internal/models"

	"github.com/go-redis/redis/v8"
)

// Issued API keys live in Redis rather than in the SQLite permission catalog
// on purpose. SQLite reaches the standby by periodic snapshot, so a key issued
// minutes before a failover would simply not exist afterwards — acceptable for
// a permission definition, not for a credential. Redis replicates
// continuously, so an issued key is on the standby immediately.
const (
	serviceAPIKeyPrefix     = "service_api_key:"
	serviceAPIKeyUsedPrefix = "service_api_key_used:"
	serviceAPIKeyScanBatch  = 100
)

var ErrAPIKeyNotFound = errors.New("api key not found")

func serviceAPIKeyKey(id string) string     { return serviceAPIKeyPrefix + id }
func serviceAPIKeyUsedKey(id string) string { return serviceAPIKeyUsedPrefix + id }

func (r *RedisRepository) StoreServiceAPIKey(ctx context.Context, key *models.ServiceAPIKey) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	client := r.client
	if client == nil {
		return errRedisClientUnavailable
	}

	payload, err := json.Marshal(key)
	if err != nil {
		return err
	}

	// No TTL: a key that has expired or been revoked is still worth keeping so
	// that it can be listed, and so a request bearing it is refused with a
	// reason rather than as an unknown id.
	return client.Set(ctx, serviceAPIKeyKey(key.ID), payload, 0).Err()
}

// GetServiceAPIKey loads a key by its public id. The last-used timestamp is
// merged in from its own key, so recording use never rewrites this record.
func (r *RedisRepository) GetServiceAPIKey(ctx context.Context, id string) (*models.ServiceAPIKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	client := r.client
	if client == nil {
		return nil, errRedisClientUnavailable
	}

	return getServiceAPIKeyWithClient(ctx, client, id)
}

func getServiceAPIKeyWithClient(ctx context.Context, client *redis.Client, id string) (*models.ServiceAPIKey, error) {
	payload, err := client.Get(ctx, serviceAPIKeyKey(id)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrAPIKeyNotFound
		}
		return nil, err
	}

	var key models.ServiceAPIKey
	if err := json.Unmarshal(payload, &key); err != nil {
		return nil, err
	}

	if raw, err := client.Get(ctx, serviceAPIKeyUsedKey(id)).Result(); err == nil {
		if used, err := time.Parse(time.RFC3339, raw); err == nil {
			key.LastUsedAt = &used
		}
	}

	return &key, nil
}

// ListServiceAPIKeys returns every issued key, newest first, without secrets.
func (r *RedisRepository) ListServiceAPIKeys(ctx context.Context) ([]*models.ServiceAPIKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	client := r.client
	if client == nil {
		return nil, errRedisClientUnavailable
	}

	keys := make([]*models.ServiceAPIKey, 0)
	var cursor uint64

	for {
		opCtx, cancel := context.WithTimeout(ctx, redisOpTimeout)
		found, nextCursor, err := client.Scan(opCtx, cursor, serviceAPIKeyPrefix+"*", serviceAPIKeyScanBatch).Result()
		cancel()
		if err != nil {
			return nil, err
		}

		for _, redisKey := range found {
			id := strings.TrimPrefix(redisKey, serviceAPIKeyPrefix)
			key, err := getServiceAPIKeyWithClient(ctx, client, id)
			if err != nil {
				continue
			}
			keys = append(keys, key)
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	sort.Slice(keys, func(i, j int) bool { return keys[i].CreatedAt.After(keys[j].CreatedAt) })
	return keys, nil
}

// RevokeServiceAPIKey marks a key unusable. It is idempotent, and it keeps the
// record so that the revocation stays visible in the admin listing.
func (r *RedisRepository) RevokeServiceAPIKey(ctx context.Context, id string) (*models.ServiceAPIKey, error) {
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()
	if client == nil {
		return nil, errRedisClientUnavailable
	}

	key, err := getServiceAPIKeyWithClient(ctx, client, id)
	if err != nil {
		return nil, err
	}
	if key.Revoked() {
		return key, nil
	}

	now := time.Now().UTC()
	key.RevokedAt = &now

	payload, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	if err := client.Set(ctx, serviceAPIKeyKey(id), payload, 0).Err(); err != nil {
		return nil, err
	}

	return key, nil
}

// ListServiceAPIKeysByTenant narrows the listing to one holder. The filter is
// applied after the scan because records are stored by id: the id is what a
// request presents, so it is what the lookup has to be keyed on.
func (r *RedisRepository) ListServiceAPIKeysByTenant(ctx context.Context, tenantID string) ([]*models.ServiceAPIKey, error) {
	all, err := r.ListServiceAPIKeys(ctx)
	if err != nil {
		return nil, err
	}

	keys := make([]*models.ServiceAPIKey, 0, len(all))
	for _, key := range all {
		if key.TenantID == tenantID {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// RevokeServiceAPIKeysByTenant revokes every key one holder has. This is the
// incident-response path: a single call, rather than reading the listing and
// revoking ids by hand while the credential is still live.
//
// A failure part way through does not discard the work already done — the
// keys that were revoked come back alongside the error, because during an
// incident "which ones are dead" is the question that matters.
func (r *RedisRepository) RevokeServiceAPIKeysByTenant(ctx context.Context, tenantID string) ([]*models.ServiceAPIKey, error) {
	keys, err := r.ListServiceAPIKeysByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	revoked := make([]*models.ServiceAPIKey, 0, len(keys))
	var failed error
	for _, key := range keys {
		updated, err := r.RevokeServiceAPIKey(ctx, key.ID)
		if err != nil {
			failed = err
			continue
		}
		revoked = append(revoked, updated)
	}
	return revoked, failed
}

// TouchServiceAPIKey records that a key was just used. It writes a dedicated
// key rather than updating the record so that concurrent requests bearing the
// same credential cannot lose each other's writes.
func (r *RedisRepository) TouchServiceAPIKey(ctx context.Context, id string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	client := r.client
	if client == nil {
		return errRedisClientUnavailable
	}

	return client.Set(ctx, serviceAPIKeyUsedKey(id), time.Now().UTC().Format(time.RFC3339), 0).Err()
}

// DeleteServiceAPIKey removes a key and its last-used marker outright. Prefer
// revocation: this leaves no trace that the credential ever existed.
func (r *RedisRepository) DeleteServiceAPIKey(ctx context.Context, id string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	client := r.client
	if client == nil {
		return errRedisClientUnavailable
	}

	pipe := client.Pipeline()
	pipe.Del(ctx, serviceAPIKeyKey(id))
	pipe.Del(ctx, serviceAPIKeyUsedKey(id))
	_, err := pipe.Exec(ctx)
	return err
}
