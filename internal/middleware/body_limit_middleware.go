package middleware

import (
	"garde/internal/models"
	"garde/pkg/errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

func LimitBodySize(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only apply to requests with bodies (POST, PUT, PATCH)
		if c.Request.ContentLength > 0 {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		}

		// Continue processing
		c.Next()

		// Check for body size errors after processing
		if err := c.Request.Body.Close(); err != nil {
			if err.Error() == "http: request body too large" {
				slog.Warn("Request body too large", "path", c.Request.URL.Path, "ip", c.ClientIP(), "content_length", c.Request.ContentLength, "max_size", maxSize)
				c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge,
					models.NewErrorResponse(errors.ErrRequestTooLarge))
				return
			}
			slog.Error("Error closing request body", "path", c.Request.URL.Path, "error", err)
		}
	}
}
