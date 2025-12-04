package middleware

import (
	"garde/internal/models"
	"garde/internal/service"
	"garde/pkg/config"
	"garde/pkg/errors"
	"garde/pkg/session"
	"log/slog"
	"net/http"
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
				slog.Debug("Auth middleware: Missing authentication", "path", c.Request.URL.Path)
				c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
				return
			}

			if !strings.HasPrefix(header, SessionPrefix) {
				slog.Debug("Auth middleware: Invalid format", "path", c.Request.URL.Path)
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

			slog.Debug("Auth middleware: Session validation failed", "path", c.Request.URL.Path, "ip", ip)
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrSessionInvalid))
			return
		}

		// Check for suspicious patterns
		if !session.IsRapidRequestCheckDisabled() && securityAnalyzer != nil {
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
				slog.Warn("Failed to track request", "error", err, "user_id", validationResult.UserID)
			}
		}

		// Check if user needs MFA setup (MFA enforced but not enabled)
		// Allow only MFA setup endpoints, user info (for frontend redirect), and logout
		path := c.Request.URL.Path
		allowedPaths := path == "/users/mfa/setup" || path == "/users/mfa/verify" || path == "/logout" || path == "/users/me"
		if !allowedPaths {
			needsMFA, err := authService.NeedsMFASetup(c.Request.Context(), validationResult.UserID)
			if err == nil && needsMFA {
				slog.Debug("Auth middleware: MFA setup required", "user_id", validationResult.UserID, "path", path)
				c.AbortWithStatusJSON(http.StatusForbidden, models.NewErrorResponse(errors.ErrMFASetupRequired))
				return
			}
		}

		// Store user ID and session ID in context for later use
		c.Set("user_id", validationResult.UserID)
		c.Set("session_id", sessionID)
		c.Next()
	}
}

func CORSMiddleware() gin.HandlerFunc {
	allowedOrigins := strings.Split(config.Get("CORS_ALLOW_ORIGINS"), ",")

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

// Applies security checks for public endpoints
func SecurityMiddleware(securityAnalyzer *service.SecurityAnalyzer) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if rapid request check or rate limiting is disabled
		if session.IsRapidRequestCheckDisabled() || config.Get("RATE_LIMIT") == "0" {
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
			slog.Warn("Failed to track request", "error", err, "ip_hash", tempID[:8])
		}

		c.Next()
	}
}
