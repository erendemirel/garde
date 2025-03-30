package middleware

import (
	"fmt"
	"garde/internal/models"
	"garde/internal/repository"
	"garde/pkg/errors"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	defaultRequestsPerMinute = 60
	rateLimitWindow          = time.Minute
	rateLimitPrefix          = "rate_limit:"
)

type RateLimiter struct {
	repo *repository.RedisRepository
}

func NewRateLimiter(repo *repository.RedisRepository) *RateLimiter {
	return &RateLimiter{
		repo: repo,
	}
}

func (rl *RateLimiter) Limit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if os.Getenv("RATE_LIMIT") == "0" {
			c.Next()
			return
		}

		ip := c.ClientIP()
		key := fmt.Sprintf("%s%s", rateLimitPrefix, ip)

		err := rl.repo.IncrementRequestCount(c.Request.Context(), key, rateLimitWindow)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.NewErrorResponse(errors.ErrOperationFailed))
			c.Abort()
			return
		}

		count, err := rl.repo.GetRequestCount(c.Request.Context(), key, rateLimitWindow)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.NewErrorResponse(errors.ErrOperationFailed))
			c.Abort()
			return
		}

		// Check if rate limit exceeded
		if count > defaultRequestsPerMinute {
			rl.repo.RecordSuspiciousActivity(c.Request.Context(), key, "rate_limit_exceeded", map[string]string{
				"ip":    ip,
				"count": fmt.Sprintf("%d", count),
			}, time.Hour)

			c.JSON(http.StatusTooManyRequests, models.NewErrorResponse(errors.ErrTooManyRequests))
			c.Abort()
			return
		}

		// Add rate limit headers
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", defaultRequestsPerMinute))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", defaultRequestsPerMinute-count))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(rateLimitWindow).Unix()))

		c.Next()
	}
}
