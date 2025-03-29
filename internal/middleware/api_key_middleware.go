package middleware

import (
	"auth_service/internal/models"
	"auth_service/pkg/errors"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

const APIKeyHeader = "X-API-Key"

func APIKeyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		apiKey := c.GetHeader(APIKeyHeader)
		if apiKey != os.Getenv("API_KEY") {
			fmt.Printf("Invalid API key\n")
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}

		c.Set("is_api_request", true)
		c.Next()
	}
}
