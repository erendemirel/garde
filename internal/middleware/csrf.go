package middleware

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"garde/internal/models"
	"garde/pkg/config"
	"garde/pkg/errors"

	"github.com/gin-gonic/gin"
)

// CookieCSRFMiddleware rejects cross-site cookie-authenticated state changes.
// Bearer and PAT requests are unaffected (no cookie CSRF surface).
//
// When SameSite=None, Origin (or Referer) is required and must match
// CORS_ALLOW_ORIGINS. For Lax/Strict, a present Origin is still checked, but a
// missing Origin is allowed so same-site / non-browser cookie clients keep working.
func CookieCSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}

		method, _ := c.Get(ContextAuthMethod)
		if method != AuthMethodCookie {
			c.Next()
			return
		}

		origin := requestOrigin(c)
		noneMode := config.GetCookieSameSite() == http.SameSiteNoneMode
		if origin == "" {
			if noneMode {
				slog.Warn("CSRF: missing Origin/Referer with SameSite=None",
					"path", c.Request.URL.Path, "method", c.Request.Method, "ip", c.ClientIP())
				c.AbortWithStatusJSON(http.StatusForbidden, models.NewErrorResponse(errors.ErrUnauthorized))
				return
			}
			c.Next()
			return
		}
		if !originAllowed(origin) {
			slog.Warn("CSRF: rejected cookie-authenticated request",
				"path", c.Request.URL.Path,
				"method", c.Request.Method,
				"origin", origin,
				"ip", c.ClientIP())
			c.AbortWithStatusJSON(http.StatusForbidden, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}
		c.Next()
	}
}

func requestOrigin(c *gin.Context) string {
	origin := strings.TrimSpace(c.Request.Header.Get("Origin"))
	if origin != "" {
		return origin
	}
	if ref := strings.TrimSpace(c.Request.Header.Get("Referer")); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Scheme != "" && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
	}
	return ""
}

func originAllowed(origin string) bool {
	for _, allowed := range strings.Split(config.Get("CORS_ALLOW_ORIGINS"), ",") {
		if strings.TrimSpace(allowed) == origin {
			return true
		}
	}
	return false
}
