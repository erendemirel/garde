package middleware

import (
	stderrors "errors"
	"garde/internal/models"
	"garde/internal/repository"
	"garde/pkg/crypto"
	"garde/pkg/errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const APIKeyHeader = "X-API-Key"

// Context keys set once a per-caller key authenticates, so that downstream
// middleware can attribute the request to the caller instead of to its IP.
const (
	ContextAPIKeyID   = "api_key_id"
	ContextAPIKeyName = "api_key_name"

	contextAPIKeyRateLimit = "api_key_rate_limit"
)

type APIKeyAuthOptions struct {
	// Repo resolves issued per-caller keys. Required: /validate no longer
	// accepts a shared configuration secret.
	Repo *repository.RedisRepository

	// RequiredScope, when set, must be carried by the presented key.
	RequiredScope string
}

// APIKeyAuth authenticates a caller from the X-API-Key header.
//
// Only issued per-caller keys (garde_<id>_<secret>) are accepted — for both
// internal services on the private listener and external tenants on a public
// /validate. Wrong-shaped or non-issued credentials are refused.
func APIKeyAuth(opts APIKeyAuthOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		presented := c.GetHeader(APIKeyHeader)
		if presented == "" {
			rejectAPIKey(c, "no API key presented")
			return
		}

		id, secret, ok := crypto.ParseAPIKey(presented)
		if !ok {
			rejectAPIKey(c, "credential is not an issued per-caller key")
			return
		}
		if opts.Repo == nil {
			rejectAPIKey(c, "per-caller key presented on a listener that cannot resolve one")
			return
		}
		authenticateServiceAPIKey(c, opts, id, secret)
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
