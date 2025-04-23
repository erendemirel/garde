package middleware

import (
	"log/slog"

	"garde/internal/models"

	"github.com/gin-gonic/gin"
)

// Hide implementation details from error responses during panic
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Log the real error internally
				slog.Error("Panic recovered in middleware",
					"error", err,
					"path", c.Request.URL.Path,
					"method", c.Request.Method,
					"ip", c.ClientIP())
				// Return generic error to client
				c.AbortWithStatusJSON(500, models.NewErrorResponse("Internal server error"))
			}
		}()
		c.Next()
	}
}
