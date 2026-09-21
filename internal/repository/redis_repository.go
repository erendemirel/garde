package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"garde/pkg/crypto"
	"garde/pkg/session"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

// Everything in this file is ephemeral state. It lives in Redis because it all
// expires on its own and losing it costs a re-login, never an account — the
// durable record is in PostgreSQL. See the Store doc comment.

const (
	maxSuspiciousRecords  = 50
	redisOpTimeout        = 3 * time.Second
	securityCodeKeyPrefix = "security_code:"
)

func tempMFAKey(userID string) string            { return "temp_mfa:" + userID }
func requestWindowKey(id string) string          { return "req_window:" + id }
func userSessionsKey(userID string) string       { return "user_sessions:" + userID }
func auditLogKey(userID string) string           { return "audit_log:" + userID }
func otpKey(userID string) string                { return "otp:" + userID }
func resetAttemptsKey(userID string) string      { return "reset_attempts:" + userID }
func lastRequestKey(userID string) string        { return "last_request:" + userID }
func suspiciousActivityKey(userID string) string { return "suspicious_activity:" + userID }

func (s *Store) getSessionDataWithClient(ctx context.Context, client *redis.Client, sessionID string) (*session.SessionData, error) {
	key := "session:" + sessionID
	keyPrefix := key
	if len(key) > 15 {
		keyPrefix = key[:15] + "..."
	}
	slog.Debug("Retrieving session data", "session_key", keyPrefix)

	jsonData, err := client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			slog.Debug("Session not found in Redis", "session_key", keyPrefix)
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

func (s *Store) StoreSessionData(ctx context.Context, sessionID string, data *session.SessionData, duration time.Duration) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %v", err)
	}

	pipe := client.Pipeline()
	pipe.Set(ctx, "session:"+sessionID, jsonData, duration)
	if data != nil && data.UserID != "" {
		idx := userSessionsKey(data.UserID)
		pipe.SAdd(ctx, idx, sessionID)
		// Keep the index at least as long as the session; refreshed on each store.
		pipe.Expire(ctx, idx, duration)
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (s *Store) GetSessionData(ctx context.Context, sessionID string) (*session.SessionData, error) {
	client := s.getClient()
	if client == nil {
		return nil, errRedisClientUnavailable
	}

	return s.getSessionDataWithClient(ctx, client, sessionID)
}

func (s *Store) DeleteSession(ctx context.Context, sessionID string) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	var userID string
	if data, err := s.getSessionDataWithClient(ctx, client, sessionID); err == nil && data != nil {
		userID = data.UserID
	}

	// Do not delete blacklist:{id} here. Callers that Blacklist then Delete rely on
	// the 24h ban surviving session removal; wiping it nullified revocation.
	pipe := client.Pipeline()
	pipe.Del(ctx, "session:"+sessionID)
	if userID != "" {
		pipe.SRem(ctx, userSessionsKey(userID), sessionID)
	}
	_, err := pipe.Exec(ctx)
	return err
}

func (s *Store) BlacklistSession(ctx context.Context, sessionID string, duration time.Duration) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	key := session.BlacklistPrefix + sessionID
	return client.Set(ctx, key, "revoked", duration).Err()
}

func (s *Store) IsSessionBlacklisted(ctx context.Context, sessionID string) (bool, error) {
	client := s.getClient()
	if client == nil {
		return false, errRedisClientUnavailable
	}

	key := session.BlacklistPrefix + sessionID
	exists, err := client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

func (s *Store) IsIPBlocked(ctx context.Context, ip string) (bool, error) {
	client := s.getClient()
	if client == nil {
		return false, errRedisClientUnavailable
	}

	key := session.IPBlockPrefix + session.HashString(ip)
	exists, err := client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

func (s *Store) BlockIP(ctx context.Context, ip string, duration time.Duration) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	key := session.IPBlockPrefix + session.HashString(ip)
	return client.Set(ctx, key, "blocked", duration).Err()
}

func (s *Store) RecordFailedLogin(ctx context.Context, email, ip string) (int64, error) {
	client := s.getClient()
	if client == nil {
		return 0, errRedisClientUnavailable
	}

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

	if len(results) < 4 {
		return 0, fmt.Errorf("unexpected pipeline result count: %d", len(results))
	}

	// Return the higher count between email and IP attempts
	emailCmd, ok := results[0].(*redis.IntCmd)
	if !ok {
		return 0, fmt.Errorf("unexpected result type for email count")
	}
	ipCmd, ok := results[2].(*redis.IntCmd)
	if !ok {
		return 0, fmt.Errorf("unexpected result type for IP count")
	}

	emailCount := emailCmd.Val()
	ipCount := ipCmd.Val()
	if ipCount > emailCount {
		return ipCount, nil
	}
	return emailCount, nil
}

func (s *Store) ClearFailedLogins(ctx context.Context, email, ip string) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	pipe := client.Pipeline()
	pipe.Del(ctx, session.FailedLoginPrefix+email)
	pipe.Del(ctx, session.FailedLoginPrefix+session.HashString(ip))
	_, err := pipe.Exec(ctx)
	return err
}

// GetFailedLoginCount returns the higher of email and IP failed-login counters
// without incrementing. Empty email or IP skips that side of the check.
func (s *Store) GetFailedLoginCount(ctx context.Context, email, ip string) (int64, error) {
	client := s.getClient()
	if client == nil {
		return 0, errRedisClientUnavailable
	}

	var emailCount, ipCount int64
	if email != "" {
		n, err := client.Get(ctx, session.FailedLoginPrefix+email).Int64()
		if err != nil && err != redis.Nil {
			return 0, err
		}
		if err == nil {
			emailCount = n
		}
	}
	if ip != "" {
		n, err := client.Get(ctx, session.FailedLoginPrefix+session.HashString(ip)).Int64()
		if err != nil && err != redis.Nil {
			return 0, err
		}
		if err == nil {
			ipCount = n
		}
	}
	if ipCount > emailCount {
		return ipCount, nil
	}
	return emailCount, nil
}

func (s *Store) RecordSuspiciousActivity(ctx context.Context, userID, activityType string, details map[string]string, ttl time.Duration) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	key := suspiciousActivityKey(userID)
	activity := map[string]any{
		"type":      activityType,
		"details":   details,
		"timestamp": time.Now(),
	}

	encoded, err := json.Marshal(activity)
	if err != nil {
		return err
	}

	// Store activity with TTL
	opCtx, cancel := context.WithTimeout(ctx, redisOpTimeout)
	defer cancel()

	pipe := client.Pipeline()
	pipe.LPush(opCtx, key, encoded)
	pipe.LTrim(opCtx, key, 0, int64(maxSuspiciousRecords-1))
	pipe.Expire(opCtx, key, ttl)
	_, err = pipe.Exec(opCtx)
	return err
}

// GetRequestCount returns how many requests were recorded for id within the sliding window.
// Used by both RATE_LIMIT (configurable window) and rapid-request detection (1 minute).
func (s *Store) GetRequestCount(ctx context.Context, id string, window time.Duration) (int64, error) {
	client := s.getClient()
	if client == nil {
		return 0, errRedisClientUnavailable
	}
	if window <= 0 {
		return 0, nil
	}

	key := requestWindowKey(id)
	cutoff := strconv.FormatInt(time.Now().Add(-window).UnixNano(), 10)
	pipe := client.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "-inf", cutoff)
	countCmd := pipe.ZCard(ctx, key)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return countCmd.Val(), nil
}

// IncrementRequestCount records a request in a Redis sorted-set sliding window of length window.
// Member scores are Unix nanoseconds. Shared by IP/user rate limiting and rapid-request tracking.
func (s *Store) IncrementRequestCount(ctx context.Context, id string, window time.Duration) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}
	if window <= 0 {
		return nil
	}

	key := requestWindowKey(id)
	now := time.Now()
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	member := fmt.Sprintf("%d-%s", now.UnixNano(), hex.EncodeToString(nonce[:]))
	cutoff := strconv.FormatInt(now.Add(-window).UnixNano(), 10)

	pipe := client.Pipeline()
	pipe.ZAdd(ctx, key, &redis.Z{Score: float64(now.UnixNano()), Member: member})
	pipe.ZRemRangeByScore(ctx, key, "-inf", cutoff)
	pipe.Expire(ctx, key, window)
	_, err := pipe.Exec(ctx)
	return err
}

func (s *Store) GetLastRequestTime(ctx context.Context, userID string) (time.Time, error) {
	client := s.getClient()
	if client == nil {
		return time.Time{}, errRedisClientUnavailable
	}

	timeStr, err := client.Get(ctx, lastRequestKey(userID)).Result()
	if err == redis.Nil {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339, timeStr)
}

func (s *Store) UpdateLastRequestTime(ctx context.Context, userID string, ttl time.Duration) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	return client.Set(ctx, lastRequestKey(userID), time.Now().Format(time.RFC3339), ttl).Err()
}

func (s *Store) GetActiveSessionInfo(ctx context.Context, userID string) (bool, string, error) {
	client := s.getClient()
	if client == nil {
		return false, "", errRedisClientUnavailable
	}

	sessionIDs, err := client.SMembers(ctx, userSessionsKey(userID)).Result()
	if err != nil {
		return false, "", err
	}

	for _, sessionID := range sessionIDs {
		sessionData, err := s.getSessionDataWithClient(ctx, client, sessionID)
		if err != nil {
			// Session expired or missing — drop stale index entry
			_ = client.SRem(ctx, userSessionsKey(userID), sessionID).Err()
			continue
		}
		return true, sessionData.IP, nil
	}

	return false, "", nil
}

func (s *Store) ClearUserSecurityData(ctx context.Context, userID, email, ip string) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	keysToDelete := []string{
		session.FailedLoginPrefix + email,
		session.FailedLoginPrefix + session.HashString(ip),
		session.IPBlockPrefix + session.HashString(ip),
		requestWindowKey(userID),
		lastRequestKey(userID),
		suspiciousActivityKey(userID),
		userSessionsKey(userID),
		resetAttemptsKey(userID),
		otpKey(userID),
	}

	var validKeys []string
	for _, key := range keysToDelete {
		if key == "" || strings.HasSuffix(key, ":") {
			continue
		}
		validKeys = append(validKeys, key)
	}

	if len(validKeys) > 0 {
		return client.Del(ctx, validKeys...).Err()
	}
	return nil
}

func (s *Store) GetUserActiveSessions(ctx context.Context, userID string) ([]string, error) {
	client := s.getClient()
	if client == nil {
		return nil, errRedisClientUnavailable
	}

	sessionIDs, err := client.SMembers(ctx, userSessionsKey(userID)).Result()
	if err != nil {
		return nil, err
	}

	var sessions []string
	for _, sessionID := range sessionIDs {
		if _, err := s.getSessionDataWithClient(ctx, client, sessionID); err != nil {
			_ = client.SRem(ctx, userSessionsKey(userID), sessionID).Err()
			continue
		}
		sessions = append(sessions, sessionID)
	}

	return sessions, nil
}

func (s *Store) StoreTempMFASecret(ctx context.Context, userID, secret string) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	enc, err := crypto.EncryptString(secret)
	if err != nil {
		return fmt.Errorf("encrypt temporary MFA secret: %w", err)
	}
	return client.Set(ctx, tempMFAKey(userID), enc, 5*time.Minute).Err()
}

func (s *Store) GetTempMFASecret(ctx context.Context, userID string) (string, error) {
	client := s.getClient()
	if client == nil {
		return "", errRedisClientUnavailable
	}

	enc, err := client.Get(ctx, tempMFAKey(userID)).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("temporary MFA secret not found or expired")
	}
	if err != nil {
		return "", err
	}
	plain, err := crypto.DecryptString(enc)
	if err != nil {
		return "", fmt.Errorf("decrypt temporary MFA secret: %w", err)
	}
	return plain, nil
}

func (s *Store) DeleteTempMFASecret(ctx context.Context, userID string) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	return client.Del(ctx, tempMFAKey(userID)).Err()
}

func (s *Store) StoreOTP(ctx context.Context, userID string, hashedOTP string) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	return client.Set(ctx, otpKey(userID), hashedOTP, 5*time.Minute).Err() // 5 minute TTL
}

func (s *Store) GetOTP(ctx context.Context, userID string) (string, error) {
	client := s.getClient()
	if client == nil {
		return "", errRedisClientUnavailable
	}

	otp, err := client.Get(ctx, otpKey(userID)).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("OTP expired or not found")
	}
	return otp, err
}

func (s *Store) DeleteOTP(ctx context.Context, userID string) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	return client.Del(ctx, otpKey(userID)).Err()
}

func (s *Store) TrackResetAttempt(ctx context.Context, userID string) (int, error) {
	client := s.getClient()
	if client == nil {
		return 0, errRedisClientUnavailable
	}

	key := resetAttemptsKey(userID)
	attempts, err := client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	// Set TTL if first attempt
	if attempts == 1 {
		client.Expire(ctx, key, 24*time.Hour)
	}

	// Check against max attempts — return the count so callers can lock; do not error here.
	return int(attempts), nil
}

func (s *Store) DeleteKey(ctx context.Context, key string) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	return client.Del(ctx, key).Err()
}

// RecordAuditLog keeps a bounded, expiring trail per user. It stays in Redis:
// it is a short window used by the security analyzer, not a compliance record.
func (s *Store) RecordAuditLog(ctx context.Context, userID string, data map[string]any, maxRecords int, ttl time.Duration) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	key := auditLogKey(userID)

	opCtx, cancel := context.WithTimeout(ctx, redisOpTimeout)
	defer cancel()

	pipe := client.Pipeline()

	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// Add new record
	pipe.LPush(opCtx, key, encoded)
	// Trim to max records
	pipe.LTrim(opCtx, key, 0, int64(maxRecords-1))
	// Reset TTL
	pipe.Expire(opCtx, key, ttl)

	_, err = pipe.Exec(opCtx)
	return err
}

func (s *Store) StoreSecurityCode(ctx context.Context, userID string, code string) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	key := securityCodeKeyPrefix + userID
	return client.Set(ctx, key, code, 15*time.Second).Err() // 15 seconds TTL
}

func (s *Store) GetSecurityCode(ctx context.Context, userID string) (string, error) {
	client := s.getClient()
	if client == nil {
		return "", errRedisClientUnavailable
	}

	key := securityCodeKeyPrefix + userID
	return client.Get(ctx, key).Result()
}

// Add distributed locking
func (s *Store) AcquireUserLock(ctx context.Context, userID string, ttl time.Duration) (bool, error) {
	client := s.getClient()
	if client == nil {
		return false, errRedisClientUnavailable
	}

	return client.SetNX(ctx, "lock:user:"+userID, "1", ttl).Result()
}

func (s *Store) ReleaseUserLock(ctx context.Context, userID string) error {
	client := s.getClient()
	if client == nil {
		return errRedisClientUnavailable
	}

	return client.Del(ctx, "lock:user:"+userID).Err()
}
