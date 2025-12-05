package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"garde/internal/models"
	"garde/pkg/config"
	"garde/pkg/session"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
)

type RedisRepository struct {
	client *redis.Client
	host   string
	port   string
	dbNum  int
	mu     sync.RWMutex
}

var errRedisClientUnavailable = errors.New("redis client not initialized")

func NewRedisRepository() (*RedisRepository, error) {
	dbNum, _ := strconv.Atoi(config.Get("REDIS_DB"))

	var host, port string
	if config.Get("DOCKER_PROFILE") == "with-redis" {
		host = "dev-redis"
		port = "6379"
	} else {
		host = config.Get("REDIS_HOST")
		port = config.Get("REDIS_PORT")
	}

	repo := &RedisRepository{
		host:  host,
		port:  port,
		dbNum: dbNum,
	}

	if err := repo.connect(); err != nil {
		return nil, err
	}

	return repo, nil
}

func (r *RedisRepository) connect() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.client != nil {
		r.client.Close()
	}

	r.client = redis.NewClient(&redis.Options{
		Addr:     r.host + ":" + r.port,
		Password: config.Get("REDIS_PASSWORD"),
		DB:       r.dbNum,
	})

	// Test connection
	ctx := context.Background()
	if err := r.client.Ping(ctx).Err(); err != nil {
		slog.Error("Redis connection error", "error", err)
		return err
	}

	slog.Info("Successfully connected to Redis", "host", r.host, "port", r.port)
	return nil
}

// Use for when secrets are rotated
func (r *RedisRepository) Reconnect() error {
	slog.Info("Redis: Reconnecting with new credentials")
	return r.connect()
}

func (r *RedisRepository) getClient() *redis.Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.client
}

func (r *RedisRepository) getSessionDataWithClient(ctx context.Context, client *redis.Client, sessionID string) (*session.SessionData, error) {
	key := "session:" + sessionID
	slog.Debug("Retrieving session data", "session_key", key[:15]+"...")

	jsonData, err := client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			slog.Debug("Session not found in Redis", "session_key", key[:15]+"...")
			return nil, errors.New("session not found")
		}
		slog.Error("Redis error retrieving session", "error", err)
		return nil, err
	}

	var sessionData session.SessionData
	if err := json.Unmarshal([]byte(jsonData), &sessionData); err != nil {
		slog.Error("Failed to unmarshal session data", "error", err)
		return nil, fmt.Errorf("failed to unmarshal session data")
	}

	slog.Debug("Successfully retrieved session", "user_id", sessionData.UserID)
	return &sessionData, nil
}

func (r *RedisRepository) getUserByIDWithClient(ctx context.Context, client *redis.Client, userID string) (*models.User, error) {
	userData, err := client.Get(ctx, "user:"+userID).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	var user models.User
	if err := json.Unmarshal(userData, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *RedisRepository) StoreUser(ctx context.Context, user *models.User) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	// Use Redis WATCH for optimistic locking
	txf := func(tx *redis.Tx) error {
		// Get current data using ID as primary key
		userKey := "user:" + user.ID
		emailIndexKey := "email_to_id:" + user.Email

		current, err := tx.Get(ctx, userKey).Result()
		if err != nil && err != redis.Nil {
			return err
		}

		if err != redis.Nil {
			var currentUser models.User
			if err := json.Unmarshal([]byte(current), &currentUser); err != nil {
				return err
			}

			// If email changed, we need to update indices
			if currentUser.Email != user.Email {
				// Remove old email index
				tx.Del(ctx, "email_to_id:"+currentUser.Email)
			}

			// Check if data was modified since we started
			if currentUser.UpdatedAt.After(user.UpdatedAt) {
				return fmt.Errorf("concurrent update detected")
			}
		}

		// Update timestamp
		user.UpdatedAt = time.Now()

		// Perform update
		userData, err := json.Marshal(user)
		if err != nil {
			return err
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			// Store user data with ID as key
			pipe.Set(ctx, userKey, userData, 0)
			// Store email to ID mapping
			pipe.Set(ctx, emailIndexKey, user.ID, 0)
			return nil
		})
		return err
	}

	// Retry mechanism for optimistic locking
	for i := 0; i < 3; i++ {
		err := client.Watch(ctx, txf, "user:"+user.ID)
		if err == nil {
			return nil
		}
		if err.Error() == "concurrent update detected" {
			return err
		}
		time.Sleep(time.Millisecond * 100 * time.Duration(i+1))
	}
	return fmt.Errorf("failed to update user after retries")
}

func (r *RedisRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return nil, errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	// Get user ID from email index
	userID, err := client.Get(ctx, "email_to_id:"+email).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return r.getUserByIDWithClient(ctx, client, userID)
}

func (r *RedisRepository) StoreSessionData(ctx context.Context, sessionID string, data *session.SessionData, duration time.Duration) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %v", err)
	}

	key := "session:" + sessionID
	return client.Set(ctx, key, jsonData, duration).Err()
}

func (r *RedisRepository) GetSessionData(ctx context.Context, sessionID string) (*session.SessionData, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return nil, errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	return r.getSessionDataWithClient(ctx, client, sessionID)
}

func (r *RedisRepository) DeleteSession(ctx context.Context, sessionID string) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	// Try to delete both session and any blacklist entry
	pipe := client.Pipeline()
	pipe.Del(ctx, "session:"+sessionID)
	pipe.Del(ctx, session.BlacklistPrefix+sessionID)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisRepository) BlacklistSession(ctx context.Context, sessionID string, duration time.Duration) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := session.BlacklistPrefix + sessionID
	return client.Set(ctx, key, "revoked", duration).Err()
}

func (r *RedisRepository) IsSessionBlacklisted(ctx context.Context, sessionID string) (bool, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return false, errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := session.BlacklistPrefix + sessionID
	exists, err := client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

func (r *RedisRepository) IsIPBlocked(ctx context.Context, ip string) (bool, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return false, errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := session.IPBlockPrefix + session.HashString(ip)
	exists, err := client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

func (r *RedisRepository) BlockIP(ctx context.Context, ip string, duration time.Duration) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := session.IPBlockPrefix + session.HashString(ip)
	return client.Set(ctx, key, "blocked", duration).Err()
}

func (r *RedisRepository) RecordFailedLogin(ctx context.Context, email, ip string) (int64, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return 0, errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := session.FailedLoginPrefix + email
	ipKey := session.FailedLoginPrefix + session.HashString(ip)

	pipe := client.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, session.FailedLoginBlockDuration)
	pipe.Incr(ctx, ipKey)
	pipe.Expire(ctx, ipKey, session.FailedLoginBlockDuration)

	results, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}

	// Return the higher count between email and IP attempts
	emailCount := results[0].(*redis.IntCmd).Val()
	ipCount := results[2].(*redis.IntCmd).Val()
	if ipCount > emailCount {
		return ipCount, nil
	}
	return emailCount, nil
}

func (r *RedisRepository) ClearFailedLogins(ctx context.Context, email, ip string) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	pipe := client.Pipeline()
	pipe.Del(ctx, session.FailedLoginPrefix+email)
	pipe.Del(ctx, session.FailedLoginPrefix+session.HashString(ip))
	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisRepository) RecordSuspiciousActivity(ctx context.Context, userID, activityType string, details map[string]string, ttl time.Duration) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := "suspicious_activity:" + userID
	activity := map[string]interface{}{
		"type":      activityType,
		"details":   details,
		"timestamp": time.Now(),
	}

	// Store activity with TTL
	pipe := client.Pipeline()
	pipe.LPush(ctx, key, activity)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisRepository) GetRequestCount(ctx context.Context, userID string, duration time.Duration) (int64, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return 0, errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := fmt.Sprintf("request_count:%s", userID)
	count, err := client.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return count, err
}

func (r *RedisRepository) IncrementRequestCount(ctx context.Context, userID string, ttl time.Duration) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := fmt.Sprintf("request_count:%s", userID)
	pipe := client.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisRepository) GetLastRequestTime(ctx context.Context, userID string) (time.Time, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return time.Time{}, errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := fmt.Sprintf("last_request:%s", userID)
	timeStr, err := client.Get(ctx, key).Result()
	if err == redis.Nil {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339, timeStr)
}

func (r *RedisRepository) UpdateLastRequestTime(ctx context.Context, userID string, ttl time.Duration) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := fmt.Sprintf("last_request:%s", userID)
	return client.Set(ctx, key, time.Now().Format(time.RFC3339), ttl).Err()
}

func (r *RedisRepository) GetActiveSessionInfo(ctx context.Context, userID string) (bool, string, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return false, "", errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	// Scan for active sessions for this user
	pattern := "session:*"
	var cursor uint64

	for {
		var keys []string
		var err error
		keys, cursor, err = client.Scan(ctx, cursor, pattern, 10).Result()
		if err != nil {
			return false, "", err
		}

		// Check each session
		for _, key := range keys {
			var sessionData session.SessionData
			data, err := client.Get(ctx, key).Bytes()
			if err != nil {
				continue
			}

			if err := json.Unmarshal(data, &sessionData); err != nil {
				continue
			}

			// If session belongs to user, return true and the IP
			if sessionData.UserID == userID {
				return true, sessionData.IP, nil
			}
		}

		if cursor == 0 {
			break
		}
	}

	return false, "", nil
}

func (r *RedisRepository) GetUserByID(ctx context.Context, userID string) (*models.User, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return nil, errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	return r.getUserByIDWithClient(ctx, client, userID)
}

func (r *RedisRepository) ClearUserSecurityData(ctx context.Context, userID, email, ip string) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	keysToDelete := []string{
		fmt.Sprintf("failed_login:%s", email),
		fmt.Sprintf("failed_login_ip:%s", ip),
		fmt.Sprintf("account_lock:%s", userID),
		fmt.Sprintf("ip_block:%s", ip),
		fmt.Sprintf("request_count:%s", userID),
		fmt.Sprintf("last_request:%s", userID),
		fmt.Sprintf("suspicious_activity:%s", userID),
		fmt.Sprintf("active_session:%s", userID),
		fmt.Sprintf("email_to_id:%s", email),
	}

	// Filter out empty keys
	var validKeys []string
	for _, key := range keysToDelete {
		if !strings.Contains(key, ":") ||
			(userID != "" && strings.Contains(key, userID)) ||
			(email != "" && strings.Contains(key, email)) {
			validKeys = append(validKeys, key)
		}
	}

	if len(validKeys) > 0 {
		return client.Del(ctx, validKeys...).Err()
	}
	return nil
}

func (r *RedisRepository) GetUserActiveSessions(ctx context.Context, userID string) ([]string, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return nil, errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	var sessions []string
	pattern := "session:*"
	var cursor uint64

	for {
		var keys []string
		var err error
		keys, cursor, err = client.Scan(ctx, cursor, pattern, 10).Result()
		if err != nil {
			return nil, err
		}

		for _, key := range keys {
			sessionData, err := r.getSessionDataWithClient(ctx, client, strings.TrimPrefix(key, "session:"))
			if err != nil {
				continue
			}

			if sessionData.UserID == userID {
				sessions = append(sessions, strings.TrimPrefix(key, "session:"))
			}
		}

		if cursor == 0 {
			break
		}
	}

	return sessions, nil
}

func (r *RedisRepository) GetLockedUsers(ctx context.Context) ([]*models.User, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return nil, errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	// Get all user keys
	keys, err := client.Keys(ctx, "user:*").Result()
	if err != nil {
		return nil, err
	}

	var users []*models.User
	for _, key := range keys {
		userData, err := client.Get(ctx, key).Result()
		if err != nil {
			continue // Skip failed reads
		}

		var user models.User
		if err := json.Unmarshal([]byte(userData), &user); err != nil {
			continue // Skip invalid data
		}

		// Only include locked users
		if user.Status != models.UserStatusOk {
			users = append(users, &user)
		}
	}

	return users, nil
}

func (r *RedisRepository) StoreTempMFASecret(ctx context.Context, userID, secret string) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := fmt.Sprintf("temp_mfa:%s", userID)
	return client.Set(ctx, key, secret, 5*time.Minute).Err() // 5 minute TTL
}

func (r *RedisRepository) GetTempMFASecret(ctx context.Context, userID string) (string, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return "", errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := fmt.Sprintf("temp_mfa:%s", userID)
	secret, err := client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("temporary MFA secret not found or expired")
	}
	return secret, err
}

func (r *RedisRepository) DeleteTempMFASecret(ctx context.Context, userID string) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := fmt.Sprintf("temp_mfa:%s", userID)
	return client.Del(ctx, key).Err()
}

func (r *RedisRepository) StoreOTP(ctx context.Context, userID string, hashedOTP string) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := fmt.Sprintf("otp:%s", userID)
	return client.Set(ctx, key, hashedOTP, 5*time.Minute).Err() // 5 minute TTL
}

func (r *RedisRepository) GetOTP(ctx context.Context, userID string) (string, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return "", errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := fmt.Sprintf("otp:%s", userID)
	otp, err := client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("OTP expired or not found")
	}
	return otp, err
}

const maxResetAttempts = 5

func (r *RedisRepository) TrackResetAttempt(ctx context.Context, userID string) (int, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return 0, errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := fmt.Sprintf("reset_attempts:%s", userID)
	attempts, err := client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	// Set TTL if first attempt
	if attempts == 1 {
		client.Expire(ctx, key, 24*time.Hour)
	}

	// Check against max attempts
	if int(attempts) > maxResetAttempts {
		return int(attempts), fmt.Errorf("max reset attempts exceeded")
	}

	return int(attempts), nil
}

func (r *RedisRepository) DeleteOTP(ctx context.Context, userID string) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := fmt.Sprintf("otp:%s", userID)
	return client.Del(ctx, key).Err()
}

func (r *RedisRepository) DeleteKey(ctx context.Context, key string) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	return client.Del(ctx, key).Err()
}

func (r *RedisRepository) RecordAuditLog(ctx context.Context, userID string, data map[string]interface{}, maxRecords int, ttl time.Duration) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := fmt.Sprintf("audit_log:%s", userID)

	pipe := client.Pipeline()

	// Add new record
	pipe.LPush(ctx, key, data)
	// Trim to max records
	pipe.LTrim(ctx, key, 0, int64(maxRecords-1))
	// Reset TTL
	pipe.Expire(ctx, key, ttl)

	_, err := pipe.Exec(ctx)
	return err
}

const securityCodeKeyPrefix = "security_code:"

func (r *RedisRepository) StoreSecurityCode(ctx context.Context, userID string, code string) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := securityCodeKeyPrefix + userID
	return client.Set(ctx, key, code, 15*time.Second).Err() // 15 seconds TTL
}

func (r *RedisRepository) GetSecurityCode(ctx context.Context, userID string) (string, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return "", errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	key := securityCodeKeyPrefix + userID
	return client.Get(ctx, key).Result()
}

func (r *RedisRepository) GetAllUsers(ctx context.Context) ([]*models.User, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return nil, errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	var users []*models.User
	var cursor uint64

	for {
		// Scan only user: keys
		keys, nextCursor, err := client.Scan(ctx, cursor, "user:*", 10).Result()
		if err != nil {
			return nil, err
		}

		for _, key := range keys {
			userData, err := client.Get(ctx, key).Bytes()
			if err != nil {
				continue
			}

			var user models.User
			if err := json.Unmarshal(userData, &user); err != nil {
				continue
			}

			users = append(users, &user)
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return users, nil
}

// Add distributed locking
func (r *RedisRepository) AcquireUserLock(ctx context.Context, userID string, ttl time.Duration) (bool, error) {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return false, errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	return client.SetNX(ctx, "lock:user:"+userID, "1", ttl).Result()
}

func (r *RedisRepository) ReleaseUserLock(ctx context.Context, userID string) error {
	r.mu.RLock()
	client := r.client
	if client == nil {
		r.mu.RUnlock()
		return errRedisClientUnavailable
	}
	defer r.mu.RUnlock()

	return client.Del(ctx, "lock:user:"+userID).Err()
}
