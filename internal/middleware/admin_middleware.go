package middleware

import (
	"log/slog"
	"net/http"

	"garde/internal/models"
	"garde/internal/service"
	"garde/pkg/errors"

	"github.com/gin-gonic/gin"
)

// Verifies that the user has admin or superuser privileges
// Assumes AuthMiddleware has already run and set is_admin/is_superuser flags
func AdminMiddleware(authService *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get admin/superuser flags set by AuthMiddleware
		isSuperUser, _ := c.Get("is_superuser")
		isAdmin, _ := c.Get("is_admin")

		isSuperUserBool, ok1 := isSuperUser.(bool)
		isAdminBool, ok2 := isAdmin.(bool)

		// If flags weren't set by AuthMiddleware, deny access
		if !ok1 || !ok2 {
			slog.Warn("AdminMiddleware: Admin flags not set by AuthMiddleware")
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}

		// If not superuser or admin, deny access
		if !isSuperUserBool && !isAdminBool {
			userID, _ := c.Get("user_id")
			slog.Info("Unauthorized access attempt to admin route", "user_id", userID)
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}

		c.Next()
	}
}
