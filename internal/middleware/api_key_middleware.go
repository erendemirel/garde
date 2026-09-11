package middleware

import (
	"crypto/subtle"
	stderrors "errors"
	"garde/internal/models"
	"garde/internal/repository"
	"garde/pkg/config"
	"garde/pkg/crypto"
	"garde/pkg/errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const APIKeyHeader = "X-API-Key"

// Context keys set once a per-tenant key authenticates, so that downstream
// middleware can attribute the request to the caller instead of to its IP.
const (
	ContextAPIKeyID   = "api_key_id"
	ContextAPIKeyName = "api_key_name"

	contextAPIKeyRateLimit = "api_key_rate_limit"
)

type APIKeyAuthOptions struct {
	// Repo resolves per-tenant keys. A nil Repo disables them, leaving only
	// the legacy shared key.
	Repo *repository.RedisRepository

	// AllowLegacyKey accepts the single shared API_KEY from configuration.
	//
	// It belongs on the private service listener and in single-listener
	// deployments. It does not belong on a public listener: one long-lived
	// secret shared by every caller, in front of an endpoint that can validate
	// any user's session, is what per-tenant keys exist to replace.
	AllowLegacyKey bool

	// RequiredScope, when set, must be carried by the presented per-tenant
	// key. The legacy shared key is not scoped and is not checked against it.
	RequiredScope string
}

// APIKeyAuth authenticates a caller from the X-API-Key header.
//
// Two kinds of credential arrive on that header, and which are accepted
// depends on the listener. A per-tenant key is recognised by its shape and
// resolved against Redis; anything else is compared against the single shared
// API_KEY from configuration, and only where AllowLegacyKey says so.
func APIKeyAuth(opts APIKeyAuthOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		presented := c.GetHeader(APIKeyHeader)
		if presented == "" {
			rejectAPIKey(c, "no API key presented")
			return
		}

		if id, secret, ok := crypto.ParseAPIKey(presented); ok {
			if opts.Repo == nil {
				rejectAPIKey(c, "per-tenant key presented on a listener that cannot resolve one")
				return
			}
			authenticateServiceAPIKey(c, opts, id, secret)
			return
		}

		if !opts.AllowLegacyKey {
			rejectAPIKey(c, "the shared API key is not accepted here")
			return
		}

		expected := config.Get("API_KEY")
		// Empty configured key must never authenticate (ConstantTimeCompare("","")==1).
		if expected == "" || subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) != 1 {
			rejectAPIKey(c, "invalid shared API key")
			return
		}

		c.Set("is_api_request", true)
		c.Next()
	}
}

func authenticateServiceAPIKey(c *gin.Context, opts APIKeyAuthOptions, id, secret string) {
	key, err := opts.Repo.GetServiceAPIKey(c.Request.Context(), id)
	if err != nil {
		if stderrors.Is(err, repository.ErrAPIKeyNotFound) {
			rejectAPIKey(c, "unknown API key id")
			return
		}
		slog.Error("Failed to look up an API key", "error", err, "api_key_id", id)
		c.AbortWithStatusJSON(http.StatusInternalServerError, models.NewErrorResponse(errors.ErrOperationFailed))
		return
	}

	// The secret is checked before revocation and expiry so that someone who
	// does not hold it learns nothing about the state of the key.
	if !crypto.APIKeySecretMatches(secret, key.SecretHash) {
		rejectAPIKey(c, "API key secret does not match")
		return
	}

	if !key.Usable(time.Now().UTC()) {
		reason := "API key expired"
		if key.Revoked() {
			reason = "API key revoked"
		}
		slog.Warn("Rejected an unusable API key", "api_key_id", id, "name", key.Name, "reason", reason)
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
		return
	}

	if opts.RequiredScope != "" && !key.HasScope(opts.RequiredScope) {
		slog.Warn("API key lacks the scope this route requires",
			"api_key_id", id, "name", key.Name, "required_scope", opts.RequiredScope)
		c.AbortWithStatusJSON(http.StatusForbidden, models.NewErrorResponse(errors.ErrAPIKeyNotPermitted))
		return
	}

	if err := opts.Repo.TouchServiceAPIKey(c.Request.Context(), id); err != nil {
		slog.Warn("Failed to record API key use", "error", err, "api_key_id", id)
	}

	c.Set("is_api_request", true)
	c.Set(ContextAPIKeyID, key.ID)
	c.Set(ContextAPIKeyName, key.Name)
	if key.RateLimit > 0 {
		c.Set(contextAPIKeyRateLimit, key.RateLimit)
	}

	c.Next()
}

// rejectAPIKey answers every failure identically. The reason is logged, never
// returned: telling a caller whether an id exists is a free enumeration oracle.
func rejectAPIKey(c *gin.Context, reason string) {
	slog.Info("Invalid API key attempt", "path", c.Request.URL.Path, "ip", c.ClientIP(), "reason", reason)
	c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
}
