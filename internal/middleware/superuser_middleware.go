package middleware

import (
	"log/slog"
	"net/http"

	"garde/internal/models"
	"garde/pkg/errors"

	"github.com/gin-gonic/gin"
)

func SuperuserMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get superuser flag set by AuthMiddleware
		isSuperUser, exists := c.Get("is_superuser")
		if !exists {
			slog.Warn("SuperuserMiddleware: Superuser flag not set by AuthMiddleware")
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}

		isSuperUserBool, ok := isSuperUser.(bool)
		if !ok || !isSuperUserBool {
			userID, _ := c.Get("user_id")
			slog.Info("Unauthorized access attempt to superuser route", "user_id", userID)
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}

		c.Next()
	}
}

