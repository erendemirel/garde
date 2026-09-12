package middleware

import (
	"garde/internal/models"
	"garde/internal/repository"
	"garde/internal/service"
	"garde/pkg/config"
	"garde/pkg/crypto"
	"garde/pkg/errors"
	"garde/pkg/session"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	AuthHeaderKey = "Authorization"
	SessionPrefix = "Bearer "
	// ContextPATID is set when the request authenticated with a personal
	// access token rather than a browser session.
	ContextPATID = "pat_id"
)

func AuthMiddleware(authService *service.AuthService, securityAnalyzer *service.SecurityAnalyzer, repo *repository.RedisRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		userAgent := c.Request.UserAgent()

		// Cookie always means session — never treat a cookie value as a PAT.
		if cookie, err := c.Cookie("session"); err == nil && cookie != "" {
			authenticateSession(c, authService, securityAnalyzer, cookie, ip, userAgent)
			return
		}

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

		presented := strings.TrimPrefix(header, SessionPrefix)

		// PATs before sessions: a garde_pat_… token must not be treated as a
		// session id (ValidateSession would fail noisily and clear cookies).
		if id, secret, ok := crypto.ParsePAT(presented); ok {
			authenticatePAT(c, authService, securityAnalyzer, repo, id, secret, ip, userAgent)
			return
		}

		// Tenant API keys belong on /validate only.
		if _, _, ok := crypto.ParseAPIKey(presented); ok {
			slog.Debug("Auth middleware: tenant API key presented on a user route", "path", c.Request.URL.Path)
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}

		authenticateSession(c, authService, securityAnalyzer, presented, ip, userAgent)
	}
}

func authenticateSession(
	c *gin.Context,
	authService *service.AuthService,
	securityAnalyzer *service.SecurityAnalyzer,
	sessionID, ip, userAgent string,
) {
	validationResult, err := authService.ValidateSession(c.Request.Context(), sessionID, ip, userAgent)
	if err != nil || validationResult == nil || !validationResult.Response.Valid {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   config.GetCookieSecure(),
			HttpOnly: true,
			SameSite: config.GetCookieSameSite(),
		})
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrSessionInvalid))
		return
	}

	if !enforceMFASetupGate(c, authService, validationResult.UserID) {
		return
	}

	if !completeUserAuth(c, authService, securityAnalyzer, validationResult.UserID, ip, userAgent) {
		return
	}

	c.Set("session_id", sessionID)
	c.Next()
}

func authenticatePAT(
	c *gin.Context,
	authService *service.AuthService,
	securityAnalyzer *service.SecurityAnalyzer,
	repo *repository.RedisRepository,
	id, secret, ip, userAgent string,
) {
	if repo == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
		return
	}

	token, err := repo.GetPAT(c.Request.Context(), id)
	if err != nil || token == nil || !token.Usable(time.Now().UTC()) ||
		!crypto.APIKeySecretMatches(secret, token.SecretHash) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
		return
	}

	if !enforceMFASetupGate(c, authService, token.UserID) {
		return
	}

	if !completeUserAuth(c, authService, securityAnalyzer, token.UserID, ip, userAgent) {
		return
	}

	if err := repo.TouchPAT(c.Request.Context(), id); err != nil {
		slog.Warn("Failed to record PAT last-used", "error", err, "pat_id", id)
	}

	c.Set(ContextPATID, id)
	c.Next()
}

func enforceMFASetupGate(c *gin.Context, authService *service.AuthService, userID string) bool {
	path := c.Request.URL.Path
	allowedPaths := path == "/users/mfa/setup" || path == "/users/mfa/verify" || path == "/logout" || path == "/users/me"
	if allowedPaths {
		return true
	}
	needsMFA, err := authService.NeedsMFASetup(c.Request.Context(), userID)
	if err == nil && needsMFA {
		slog.Debug("Auth middleware: MFA setup required", "user_id", userID, "path", path)
		c.AbortWithStatusJSON(http.StatusForbidden, models.NewErrorResponse(errors.ErrMFASetupRequired))
		return false
	}
	return true
}

func completeUserAuth(
	c *gin.Context,
	authService *service.AuthService,
	securityAnalyzer *service.SecurityAnalyzer,
	userID, ip, userAgent string,
) bool {
	user, err := authService.GetCurrentUser(c.Request.Context(), userID)
	if err != nil {
		slog.Warn("AuthMiddleware: Failed to get current user", "user_id", userID, "error", err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
		return false
	}

	if user.Status != models.UserStatusOk {
		slog.Info("AuthMiddleware: Rejecting non-ok user status", "user_id", user.ID, "status", user.Status)
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrAccessRestricted))
		return false
	}

	superUserEmail := config.Get("SUPERUSER_EMAIL")
	isSuperUser := user.Email == superUserEmail
	isAdmin := user.IsUserAdmin()

	c.Set("is_superuser", isSuperUser)
	c.Set("is_admin", isAdmin)

	if isAdmin {
		scopes, enforced := config.AdminScopesFor(user.Email)
		c.Set(contextAdminScopes, scopes)
		c.Set(contextAdminScopesEnforced, enforced)
	}

	if !session.IsRapidRequestCheckDisabled() && securityAnalyzer != nil {
		patterns := securityAnalyzer.DetectSuspiciousPatternsWithRole(c.Request.Context(), userID, ip, userAgent, isAdmin, isSuperUser)
		if len(patterns) > 0 {
			slog.Warn("AuthMiddleware: Suspicious patterns detected, blocking request", "user_id", userID, "path", c.Request.URL.Path, "patterns", patterns)
			for _, pattern := range patterns {
				securityAnalyzer.RecordPattern(c.Request.Context(), userID, pattern, ip, userAgent)
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrAccessRestricted))
			return false
		}

		if err := securityAnalyzer.TrackRequest(c.Request.Context(), userID); err != nil {
			slog.Warn("Failed to track request", "error", err, "user_id", userID)
		}
	} else {
		slog.Debug("AuthMiddleware: Security analyzer check skipped", "rapid_check_disabled", session.IsRapidRequestCheckDisabled(), "analyzer_nil", securityAnalyzer == nil)
	}

	c.Set("user_id", userID)
	return true
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		for _, allowedOrigin := range strings.Split(config.Get("CORS_ALLOW_ORIGINS"), ",") {
			if strings.TrimSpace(allowedOrigin) == origin {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}

		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		if config.GetBool("USE_TLS") {
			c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
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
		if session.IsRapidRequestCheckDisabled() || IsRateLimitDisabled() {
			c.Next()
			return
		}

		ip := c.ClientIP()
		userAgent := c.Request.UserAgent()

		tempID := session.HashString(ip + userAgent)

		patterns := securityAnalyzer.DetectSuspiciousPatterns(c.Request.Context(), tempID, ip, userAgent)
		if len(patterns) > 0 {
			for _, pattern := range patterns {
				securityAnalyzer.RecordPattern(c.Request.Context(), tempID, pattern, ip, userAgent)
			}
			c.AbortWithStatusJSON(http.StatusTooManyRequests, models.NewErrorResponse(errors.ErrTooManyRequests))
			return
		}

		if err := securityAnalyzer.TrackRequest(c.Request.Context(), tempID); err != nil {
			slog.Warn("Failed to track request", "error", err, "ip_hash", tempID[:8])
		}

		c.Next()
	}
}
