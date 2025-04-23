package middleware

import (
	"log/slog"
	"net/http"
	"os"
	"strings"

	"garde/internal/models"
	"garde/internal/service"
	"garde/pkg/errors"

	"github.com/gin-gonic/gin"
)

// Verifies that the user is authenticated and has admin or superuser privileges
func AdminMiddleware(authService *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {

		// Get session ID from cookie or header
		var sessionID string
		if cookie, err := c.Cookie("session"); err == nil {
			sessionID = cookie
		} else {
			header := c.GetHeader("Authorization")
			if header == "" || !strings.HasPrefix(header, "Bearer ") {
				slog.Debug("No session cookie or valid Authorization header found")
				c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
				return
			}
			sessionID = strings.TrimPrefix(header, "Bearer ")
		}

		// Validate session and get userID
		validationResult, err := authService.ValidateSession(c, sessionID, c.ClientIP(), c.Request.UserAgent())
		if err != nil || validationResult == nil || !validationResult.Response.Valid {
			slog.Debug("Session validation failed", "error", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}
		userID := validationResult.UserID
		slog.Debug("Session validated successfully", "user_id", userID)

		// Get user from repository
		user, err := authService.GetCurrentUser(c, userID)
		if err != nil {
			slog.Warn("Failed to get user", "user_id", userID, "error", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}

		// Check if user is superuser
		superUserEmail := os.Getenv("SUPERUSER_EMAIL")
		isSuperUser := user.Email == superUserEmail

		// Check if user is in ADMIN_USERS list
		adminUsersEnv := os.Getenv("ADMIN_USERS")
		adminUsers := strings.Split(adminUsersEnv, ",")

		isAdmin := false
		for _, adminEmail := range adminUsers {
			adminEmail = strings.TrimSpace(adminEmail)
			if adminEmail == user.Email {
				isAdmin = true
				break
			}
		}

		// If not superuser or admin, deny access
		if !isSuperUser && !isAdmin {
			slog.Info("Unauthorized access attempt to admin route", "user_id", userID, "email", user.Email)
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}

		// Store admin status in context
		c.Set("is_superuser", isSuperUser)
		c.Set("is_admin", isAdmin)
		c.Set("user_id", userID)
		c.Set("session_id", sessionID)
		c.Next()
	}
}
