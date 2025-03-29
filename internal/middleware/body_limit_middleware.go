package middleware

import (
	"auth_service/internal/models"
	"auth_service/pkg/errors"
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
				c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge,
					models.NewErrorResponse(errors.ErrRequestTooLarge))
				return
			}
		}
	}
}
