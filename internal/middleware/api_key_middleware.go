package middleware

import (
	"garde/internal/models"
	"garde/pkg/config"
	"garde/pkg/errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

const APIKeyHeader = "X-API-Key"

func APIKeyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		apiKey := c.GetHeader(APIKeyHeader)
		if apiKey != config.Get("API_KEY") {
			slog.Info("Invalid API key attempt", "path", c.Request.URL.Path, "ip", c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}

		c.Set("is_api_request", true)
		c.Next()
	}
}
