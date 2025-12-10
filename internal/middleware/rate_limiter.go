package middleware

import (
	"fmt"
	"garde/internal/models"
	"garde/internal/repository"
	"garde/pkg/config"
	"garde/pkg/errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	defaultRequestsPerWindow     = 60
	defaultWindowSeconds         = 60
	defaultAuthenticatedRequests = 300  // Higher limit for authenticated users
	defaultAdminRequests         = 1000 // Even higher for admins/superusers
	rateLimitPrefix              = "rate_limit:"
)

type RateLimiter struct {
	repo                 *repository.RedisRepository
	maxReqs              int
	authenticatedMaxReqs int
	adminMaxReqs         int
	windowSize           time.Duration
}

// Format: "limit" or "limit,window_seconds" or "limit,window_seconds,auth_limit,admin_limit"
// e.g. "100,60" means 100 requests per 60 seconds for unauthenticated
// e.g. "100,60,300,1000" means 100 for unauthenticated, 300 for authenticated, 1000 for admins
// Use "0" or "0,0" to disable rate limiting
func NewRateLimiter(repo *repository.RedisRepository) *RateLimiter {
	maxReqs := defaultRequestsPerWindow
	authenticatedMaxReqs := defaultAuthenticatedRequests
	adminMaxReqs := defaultAdminRequests
	windowSecs := defaultWindowSeconds

	if envLimit := config.Get("RATE_LIMIT"); envLimit != "" {
		parts := strings.Split(envLimit, ",")
		if len(parts) >= 1 {
			if parsed, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil && parsed >= 0 {
				maxReqs = parsed
			}
		}
		if len(parts) >= 2 {
			if parsed, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && parsed > 0 {
				windowSecs = parsed
			}
		}
		if len(parts) >= 3 {
			if parsed, err := strconv.Atoi(strings.TrimSpace(parts[2])); err == nil && parsed > 0 {
				authenticatedMaxReqs = parsed
			}
		}
		if len(parts) >= 4 {
			if parsed, err := strconv.Atoi(strings.TrimSpace(parts[3])); err == nil && parsed > 0 {
				adminMaxReqs = parsed
			}
		}
	}

	return &RateLimiter{
		repo:                 repo,
		maxReqs:              maxReqs,
		authenticatedMaxReqs: authenticatedMaxReqs,
		adminMaxReqs:         adminMaxReqs,
		windowSize:           time.Duration(windowSecs) * time.Second,
	}
}

func (rl *RateLimiter) Limit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if rl.maxReqs == 0 {
			c.Next()
			return
		}

		ip := c.ClientIP()
		key := fmt.Sprintf("%s%s", rateLimitPrefix, ip)

		err := rl.repo.IncrementRequestCount(c.Request.Context(), key, rl.windowSize)
		if err != nil {
			slog.Error("Failed to increment rate limit count", "error", err, "ip", ip)
			c.JSON(http.StatusInternalServerError, models.NewErrorResponse(errors.ErrOperationFailed))
			c.Abort()
			return
		}

		count, err := rl.repo.GetRequestCount(c.Request.Context(), key, rl.windowSize)
		if err != nil {
			slog.Error("Failed to get rate limit count", "error", err, "ip", ip)
			c.JSON(http.StatusInternalServerError, models.NewErrorResponse(errors.ErrOperationFailed))
			c.Abort()
			return
		}

		// Check if rate limit exceeded
		if count > int64(rl.maxReqs) {
			slog.Warn("Rate limit exceeded", "ip", ip, "count", count, "limit", rl.maxReqs)

			err := rl.repo.RecordSuspiciousActivity(c.Request.Context(), key, "rate_limit_exceeded", map[string]string{
				"ip":    ip,
				"count": fmt.Sprintf("%d", count),
			}, time.Hour)

			if err != nil {
				slog.Error("Failed to record rate limit suspicious activity", "error", err, "ip", ip)
			}

			c.JSON(http.StatusTooManyRequests, models.NewErrorResponse(errors.ErrTooManyRequests))
			c.Abort()
			return
		}

		// Add rate limit headers
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", rl.maxReqs))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", int64(rl.maxReqs)-count))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(rl.windowSize).Unix()))

		c.Next()
	}
}
