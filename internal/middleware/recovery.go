package middleware

import (
	"log"

	"github.com/gin-gonic/gin"
	"garde/internal/models"
)

// Hide implementation details from error responses during panic
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Log the real error internally
				log.Printf("Panic recovered: %v", err)
				// Return generic error to client
				c.AbortWithStatusJSON(500, models.NewErrorResponse("Internal server error"))
			}
		}()
		c.Next()
	}
} 