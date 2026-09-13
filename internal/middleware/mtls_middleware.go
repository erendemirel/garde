package middleware

import (
	"log/slog"
	"net/http"
	"strings"

	"garde/internal/models"
	"garde/pkg/config"
	"garde/pkg/errors"

	"github.com/gin-gonic/gin"
)

// Verifies that the request includes a valid mTLS certificate whose DNS SAN
// matches DOMAIN_NAME. Common Name is not accepted (deprecated X.509 practice).
func MTLSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		slog.Debug("MTLSMiddleware: Processing request", "path", c.Request.URL.Path)

		if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 || len(c.Request.TLS.VerifiedChains) == 0 {
			slog.Warn("mTLS validation failed: Client certificate not present, valid, or verified", "ip", c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}

		clientCert := c.Request.TLS.PeerCertificates[0]
		serverDomain := config.Get("DOMAIN_NAME")

		domainValid := false
		for _, san := range clientCert.DNSNames {
			if strings.EqualFold(san, serverDomain) {
				domainValid = true
				break
			}
		}

		slog.Debug("mTLS domain validation",
			"domain_match", domainValid,
			"expected_domain", serverDomain)

		if !domainValid {
			slog.Warn("mTLS certificate domain mismatch",
				"expected_domain", serverDomain,
				"ip", c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}

		c.Next()
	}
}
