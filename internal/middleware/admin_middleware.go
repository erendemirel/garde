package middleware

import (
	"fmt"
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
		fmt.Printf("AdminMiddleware: Processing request to %s\n", c.Request.URL.Path)

		// Get session ID from cookie or header
		var sessionID string
		if cookie, err := c.Cookie("session"); err == nil {
			sessionID = cookie
			fmt.Printf("Using session from cookie: %s (first 10 chars)\n", sessionID[:10])
		} else {
			header := c.GetHeader("Authorization")
			if header == "" || !strings.HasPrefix(header, "Bearer ") {
				fmt.Printf("No session cookie or valid Authorization header found\n")
				c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
				return
			}
			sessionID = strings.TrimPrefix(header, "Bearer ")
			fmt.Printf("Using session from Authorization header: %s (first 10 chars)\n", sessionID[:10])
		}

		// Validate session and get userID
		fmt.Printf("Validating session in AdminMiddleware: %s (first 10 chars)\n", sessionID[:10])
		validationResult, err := authService.ValidateSession(c, sessionID, c.ClientIP(), c.Request.UserAgent())
		if err != nil || validationResult == nil || !validationResult.Response.Valid {
			fmt.Printf("Session validation failed\n")
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}
		userID := validationResult.UserID
		fmt.Printf("Session validated successfully for user: %s\n", userID)

		// Get user from repository
		user, err := authService.GetCurrentUser(c, userID)
		if err != nil {
			fmt.Printf("Failed to get user: %v\n", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}

		// Check if user is superuser
		superUserEmail := os.Getenv("SUPERUSER_EMAIL")
		isSuperUser := user.Email == superUserEmail
		fmt.Printf("DEBUG: AdminMiddleware - user email: %s, superuser email from env: %s, is superuser: %v\n",
			user.Email, superUserEmail, isSuperUser)

		// Check if user is in ADMIN_USERS list
		adminUsersEnv := os.Getenv("ADMIN_USERS")
		adminUsers := strings.Split(adminUsersEnv, ",")
		fmt.Printf("DEBUG: AdminMiddleware - ADMIN_USERS from env: %s\n", adminUsersEnv)

		isAdmin := false
		for _, adminEmail := range adminUsers {
			adminEmail = strings.TrimSpace(adminEmail)
			fmt.Printf("DEBUG: AdminMiddleware - checking admin email: '%s' against user email: '%s'\n",
				adminEmail, user.Email)
			if adminEmail == user.Email {
				isAdmin = true
				break
			}
		}
		fmt.Printf("DEBUG: AdminMiddleware - user is admin: %v\n", isAdmin)

		// If not superuser or admin, deny access
		if !isSuperUser && !isAdmin {
			fmt.Printf("DEBUG: AdminMiddleware - User %s is not a superuser or admin, denying access\n", user.Email)
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
