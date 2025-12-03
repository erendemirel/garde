package service

import (
	"context"
	"fmt"
	"garde/internal/repository"
	"garde/pkg/session"
	"log/slog"
	"os"
	"strings"
	"time"
)

type SecurityAnalyzer struct {
	repo *repository.RedisRepository
}

func NewSecurityAnalyzer(repo *repository.RedisRepository) *SecurityAnalyzer {
	return &SecurityAnalyzer{repo: repo}
}

const (
	multipleIPPattern = "multiple_ip_sessions"
	// TTLs for security records
	requestCountTTL       = 24 * time.Hour
	lastRequestTimeTTL    = 24 * time.Hour
	suspiciousActivityTTL = 48 * time.Hour

	// Add audit logging with longer retention
	maxAuditRecords = 10
	auditLogTTL     = 30 * 24 * time.Hour // 30 days
)

func (d *SecurityAnalyzer) DetectSuspiciousPatterns(ctx context.Context, userID, ip, userAgent string) []string {
	var patterns []string

	// 1. Check for rapid requests (potential automated attack)
	if !session.IsRapidRequestCheckDisabled() {
		requestCount, err := d.repo.GetRequestCount(ctx, userID, time.Minute)
		if err != nil {
			slog.Debug("Failed to get request count", "error", err, "user_id", userID)
		}
		if requestCount > session.RapidRequestThreshold {
			slog.Warn("Rapid request pattern detected", "user_id", userID, "count", requestCount)
			patterns = append(patterns, session.ActivityRapidRequests)
		}
	}

	// 2. Check for automated behavior (requests too fast for human)
	if !session.IsRapidRequestCheckDisabled() {
		lastRequestTime, err := d.repo.GetLastRequestTime(ctx, userID)
		if err != nil {
			slog.Debug("Failed to get last request time", "error", err, "user_id", userID)
		}
		if !lastRequestTime.IsZero() && time.Since(lastRequestTime) < session.AutomatedRequestTimeout {
			slog.Warn("Automated behavior pattern detected", "user_id", userID, "time_since_last", time.Since(lastRequestTime))
			patterns = append(patterns, session.ActivityAutomatedBehavior)
		}
	}

	// 3. Check for unusual User-Agent patterns
	if d.isUnusualUserAgent(userAgent) {
		slog.Warn("Unusual user agent detected", "user_id", userID, "user_agent", userAgent)
		patterns = append(patterns, session.ActivityUnusualUserAgent)
	}

	// 4. Check for multiple IP sessions
	if os.Getenv("DISABLE_MULTIPLE_IP_CHECK") != "true" {
		hasActiveSession, activeIP, err := d.repo.GetActiveSessionInfo(ctx, userID)
		if err != nil {
			slog.Debug("Failed to get active session info", "error", err, "user_id", userID)
		}
		if hasActiveSession && activeIP != session.HashString(ip) {
			slog.Warn("Multiple IP session pattern detected", "user_id", userID, "new_ip_hash", session.HashString(ip))
			patterns = append(patterns, multipleIPPattern)
		}
	}

	if len(patterns) > 0 {
		slog.Info("Suspicious patterns detected", "user_id", userID, "patterns", patterns)
	}

	return patterns
}

func (d *SecurityAnalyzer) isUnusualUserAgent(userAgent string) bool {
	if os.Getenv("DISABLE_USER_AGENT_CHECK") == "true" {
		return false
	}

	userAgent = strings.ToLower(userAgent)

	// Check for common bot/script identifiers
	suspiciousTerms := []string{
		"bot", "crawler", "spider", "headless",
		"phantomjs", "selenium", "puppet",
		"curl", "wget", "python-requests",
	}

	for _, term := range suspiciousTerms {
		if strings.Contains(userAgent, term) {
			return true
		}
	}

	// Check for missing common browser identifiers
	commonBrowsers := []string{
		"mozilla", "chrome", "safari", "firefox", "edge",
	}

	hasCommonBrowser := false
	for _, browser := range commonBrowsers {
		if strings.Contains(userAgent, browser) {
			hasCommonBrowser = true
			break
		}
	}

	return !hasCommonBrowser
}

func (d *SecurityAnalyzer) TrackRequest(ctx context.Context, userID string) error {
	if session.IsRapidRequestCheckDisabled() {
		return nil
	}

	if err := d.repo.IncrementRequestCount(ctx, userID, requestCountTTL); err != nil {
		slog.Debug("Failed to increment request count", "error", err, "user_id", userID)
		return fmt.Errorf("failed to increment request count")
	}
	if err := d.repo.UpdateLastRequestTime(ctx, userID, lastRequestTimeTTL); err != nil {
		slog.Debug("Failed to update last request time", "error", err, "user_id", userID)
		return fmt.Errorf("failed to update last request time")
	}
	return nil
}

func (d *SecurityAnalyzer) RecordPattern(ctx context.Context, userID, pattern, ip, userAgent string) error {
	slog.Info("Recording security pattern", "user_id", userID, "pattern", pattern, "ip", ip)

	// Record for active security measures (TTL-based)
	if err := d.repo.RecordSuspiciousActivity(ctx, userID, pattern, map[string]string{
		"ip":         ip,
		"user_agent": userAgent,
		"pattern":    pattern,
	}, suspiciousActivityTTL); err != nil {
		slog.Error("Failed to record suspicious activity", "error", err, "user_id", userID, "pattern", pattern)
		return err
	}

	// Also record in audit log (last N records with longer TTL)
	if err := d.repo.RecordAuditLog(ctx, userID, map[string]interface{}{
		"type":       "security_pattern",
		"pattern":    pattern,
		"ip":         ip,
		"user_agent": userAgent,
		"timestamp":  time.Now(),
	}, maxAuditRecords, auditLogTTL); err != nil {
		slog.Error("Failed to record audit log", "error", err, "user_id", userID, "pattern", pattern)
		return err
	}

	return nil
}

func (d *SecurityAnalyzer) CleanupSecurityRecords(ctx context.Context, userID, email, ip string) error {
	slog.Debug("Cleaning up security records", "user_id", userID, "email", email, "ip", ip)

	// Clean up analyzer-specific records
	analyzerKeys := []string{
		fmt.Sprintf("request_count:%s", userID),
		fmt.Sprintf("last_request:%s", userID),
		fmt.Sprintf("suspicious_activity:%s", userID),
	}

	// Clean up other security-related records
	securityKeys := []string{
		fmt.Sprintf("failed_login:%s", email),
		fmt.Sprintf("failed_login_ip:%s", ip),
		fmt.Sprintf("account_lock:%s", email),
		fmt.Sprintf("ip_block:%s", ip),
		fmt.Sprintf("active_session:%s", email),
	}

	// Combine all keys
	keys := append(analyzerKeys, securityKeys...)

	// Filter out empty keys (when email or ip is not provided)
	var validKeys []string
	for _, key := range keys {
		if !strings.Contains(key, ":") || strings.Contains(key, userID) {
			validKeys = append(validKeys, key)
		}
	}

	if len(validKeys) > 0 {
		for _, key := range validKeys {
			if err := d.repo.DeleteKey(ctx, key); err != nil {
				slog.Warn("Failed to delete security record", "error", err, "key", key)
				return fmt.Errorf("failed to cleanup security records")
			}
		}
	}

	return nil
}
