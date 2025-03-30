package middleware

import (
	"fmt"
	"garde/internal/models"
	"garde/internal/service"
	"garde/pkg/errors"
	"garde/pkg/session"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	AuthHeaderKey = "Authorization"
	SessionPrefix = "Bearer "
)

func AuthMiddleware(authService *service.AuthService, securityAnalyzer *service.SecurityAnalyzer) gin.HandlerFunc {
	return func(c *gin.Context) {
		var sessionID string

		// First try to get session from cookie
		cookie, err := c.Cookie("session")
		if err == nil {
			sessionID = cookie
		} else {
			// Fallback to Authorization header
			header := c.GetHeader(AuthHeaderKey)
			if header == "" {
				fmt.Printf("Auth middleware: Missing authentication\n")
				c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
				return
			}

			if !strings.HasPrefix(header, SessionPrefix) {
				fmt.Printf("Auth middleware: Invalid format\n")
				c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrInvalidRequest))
				return
			}

			sessionID = strings.TrimPrefix(header, SessionPrefix)
		}

		// Get IP and User-Agent
		ip := c.ClientIP()
		userAgent := c.Request.UserAgent()

		// Validate session and get userID
		validationResult, err := authService.ValidateSession(c.Request.Context(), sessionID, ip, userAgent)
		if err != nil || validationResult == nil || !validationResult.Response.Valid {
			// Clear cookie if session is invalid
			c.SetCookie(
				"session",
				"",
				-1,
				"/",
				"", // Empty domain
				true,
				true,
			)

			fmt.Printf("Auth middleware: Session validation failed\n")
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrSessionInvalid))
			return
		}

		// Check for suspicious patterns
		if os.Getenv("DISABLE_RAPID_REQUEST_CHECK") != "true" && securityAnalyzer != nil {
			patterns := securityAnalyzer.DetectSuspiciousPatterns(c.Request.Context(), validationResult.UserID, ip, userAgent)
			if len(patterns) > 0 {
				// Record all detected patterns
				for _, pattern := range patterns {
					securityAnalyzer.RecordPattern(c.Request.Context(), validationResult.UserID, pattern, ip, userAgent)
				}
				c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrAccessRestricted))
				return
			}

			// Track legitimate request
			if err := securityAnalyzer.TrackRequest(c.Request.Context(), validationResult.UserID); err != nil {
				fmt.Printf("Failed to track request: %v\n", err)
			}
		}

		// Store user ID and session ID in context for later use
		c.Set("user_id", validationResult.UserID)
		c.Set("session_id", sessionID)
		c.Next()
	}
}

func CORSMiddleware() gin.HandlerFunc {
	allowedOrigins := strings.Split(os.Getenv("CORS_ALLOW_ORIGINS"), ",")

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		// Check if the request origin is in the allowed list
		for _, allowedOrigin := range allowedOrigins {
			if strings.TrimSpace(allowedOrigin) == origin {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}

		// CORS headers
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		// Security headers
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func ConditionalAuthMiddleware(authService *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get email from request body
		var body struct {
			Email string `json:"email"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, models.NewErrorResponse(errors.ErrInvalidRequest))
			return
		}

		// Check if user needs MFA setup
		needsMFASetup, err := authService.NeedsMFASetup(c.Request.Context(), body.Email)
		if err != nil || !needsMFASetup {
			// If error or doesn't need setup, require normal authentication
			AuthMiddleware(authService, nil)(c)
			return
		}

		// Allow request to proceed without authentication
		c.Next()
	}
}

// Applies security checks for public endpoints
func SecurityMiddleware(securityAnalyzer *service.SecurityAnalyzer) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if rapid request check or rate limiting is disabled
		if os.Getenv("DISABLE_RAPID_REQUEST_CHECK") == "true" || os.Getenv("RATE_LIMIT") == "0" {
			c.Next()
			return
		}

		ip := c.ClientIP()
		userAgent := c.Request.UserAgent()

		// For public endpoints, we can only check IP and User-Agent patterns
		// We'll create a temporary ID based on IP for tracking
		tempID := session.HashString(ip + userAgent)

		patterns := securityAnalyzer.DetectSuspiciousPatterns(c.Request.Context(), tempID, ip, userAgent)
		if len(patterns) > 0 {
			// Record suspicious patterns
			for _, pattern := range patterns {
				securityAnalyzer.RecordPattern(c.Request.Context(), tempID, pattern, ip, userAgent)
			}
			c.AbortWithStatusJSON(http.StatusTooManyRequests, models.NewErrorResponse(errors.ErrTooManyRequests))
			return
		}

		// Track request
		if err := securityAnalyzer.TrackRequest(c.Request.Context(), tempID); err != nil {
			fmt.Printf("Failed to track request: %v\n", err)
		}

		c.Next()
	}
}
