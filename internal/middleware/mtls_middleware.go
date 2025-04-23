package middleware

import (
	"log/slog"
	"net/http"
	"os"
	"strings"

	"garde/internal/models"
	"garde/pkg/errors"

	"github.com/gin-gonic/gin"
)

// Verifies that the request includes a valid mTLS certificate
func MTLSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		slog.Debug("MTLSMiddleware: Processing request", "path", c.Request.URL.Path)

		// Verify mTLS
		if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 || len(c.Request.TLS.VerifiedChains) == 0 {
			slog.Warn("mTLS validation failed: Client certificate not present, valid, or verified", "ip", c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}

		// Verify certificate domain
		clientCert := c.Request.TLS.PeerCertificates[0]
		serverDomain := os.Getenv("DOMAIN_NAME")

		// Check if we're in testing mode
		isTestingMode := strings.ToLower(os.Getenv("TESTING_MODE")) == "true"

		var domainValid bool

		if isTestingMode {
			// In testing mode, just compare the Common Name directly with the domain
			domainValid = strings.EqualFold(clientCert.Subject.CommonName, serverDomain)
			slog.Debug("mTLS testing mode validation",
				"domain_match", domainValid,
				"expected_domain", serverDomain)
		} else {
			// In production mode, do more thorough validation
			// Check CN
			domainValid = strings.EqualFold(clientCert.Subject.CommonName, serverDomain)

			// If CN doesn't match exactly, check if it's a subdomain or related domain
			if !domainValid {
				extractedDomain := extractDomain(clientCert.Subject.CommonName)
				domainValid = strings.EqualFold(extractedDomain, serverDomain)
			}

			// Also check SANs (Subject Alternative Names) if present
			for _, san := range clientCert.DNSNames {
				if strings.EqualFold(san, serverDomain) {
					domainValid = true
					break
				}
			}

			slog.Debug("mTLS production mode validation",
				"domain_match", domainValid,
				"expected_domain", serverDomain)
		}

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

func extractDomain(cn string) string {
	// Remove any prefixes (like service names) from CN
	parts := strings.Split(cn, ".")
	if len(parts) < 2 {
		return cn
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
