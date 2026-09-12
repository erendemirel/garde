package repository

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"garde/internal/models"

	"github.com/go-redis/redis/v8"
)

// PATs live in Redis for the same reason as tenant API keys: continuous
// replication, not SQLite's snapshot window.
const (
	userPATPrefix     = "user_pat:"
	userPATUsedPrefix = "user_pat_used:"
	userPATsSetPrefix = "user_pats:"
)

var ErrPATNotFound = errors.New("personal access token not found")

func userPATKey(id string) string     { return userPATPrefix + id }
func userPATUsedKey(id string) string { return userPATUsedPrefix + id }
func userPATsSetKey(userID string) string { return userPATsSetPrefix + userID }

func (r *RedisRepository) StorePAT(ctx context.Context, token *models.PersonalAccessToken) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	client := r.client
	if client == nil {
		return errRedisClientUnavailable
	}

	payload, err := json.Marshal(token)
	if err != nil {
		return err
	}

	pipe := client.Pipeline()
	pipe.Set(ctx, userPATKey(token.ID), payload, 0)
	pipe.SAdd(ctx, userPATsSetKey(token.UserID), token.ID)
	_, err = pipe.Exec(ctx)
	return err
}

func (r *RedisRepository) GetPAT(ctx context.Context, id string) (*models.PersonalAccessToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	client := r.client
	if client == nil {
		return nil, errRedisClientUnavailable
	}
	return getPATWithClient(ctx, client, id)
}

func getPATWithClient(ctx context.Context, client *redis.Client, id string) (*models.PersonalAccessToken, error) {
	payload, err := client.Get(ctx, userPATKey(id)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrPATNotFound
		}
		return nil, err
	}

	var token models.PersonalAccessToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, err
	}

	if raw, err := client.Get(ctx, userPATUsedKey(id)).Result(); err == nil {
		if used, err := time.Parse(time.RFC3339, raw); err == nil {
			token.LastUsedAt = &used
		}
	}

	return &token, nil
}

// ListPATsByUser returns every token the user has issued, newest first.
func (r *RedisRepository) ListPATsByUser(ctx context.Context, userID string) ([]*models.PersonalAccessToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	client := r.client
	if client == nil {
		return nil, errRedisClientUnavailable
	}

	ids, err := client.SMembers(ctx, userPATsSetKey(userID)).Result()
	if err != nil {
		return nil, err
	}

	tokens := make([]*models.PersonalAccessToken, 0, len(ids))
	for _, id := range ids {
		token, err := getPATWithClient(ctx, client, id)
		if err != nil {
			continue
		}
		tokens = append(tokens, token)
	}

	sort.Slice(tokens, func(i, j int) bool {
		return tokens[i].CreatedAt.After(tokens[j].CreatedAt)
	})
	return tokens, nil
}

func (r *RedisRepository) CountPATsByUser(ctx context.Context, userID string) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	client := r.client
	if client == nil {
		return 0, errRedisClientUnavailable
	}
	n, err := client.SCard(ctx, userPATsSetKey(userID)).Result()
	return int(n), err
}

func (r *RedisRepository) RevokePAT(ctx context.Context, id, userID string) (*models.PersonalAccessToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	client := r.client
	if client == nil {
		return nil, errRedisClientUnavailable
	}

	token, err := getPATWithClient(ctx, client, id)
	if err != nil {
		return nil, err
	}
	if token.UserID != userID {
		return nil, ErrPATNotFound
	}
	if token.Revoked() {
		return token, nil
	}

	now := time.Now().UTC()
	token.RevokedAt = &now
	payload, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}
	if err := client.Set(ctx, userPATKey(id), payload, 0).Err(); err != nil {
		return nil, err
	}
	return token, nil
}

func (r *RedisRepository) TouchPAT(ctx context.Context, id string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	client := r.client
	if client == nil {
		return errRedisClientUnavailable
	}
	return client.Set(ctx, userPATUsedKey(id), time.Now().UTC().Format(time.RFC3339), 0).Err()
}
