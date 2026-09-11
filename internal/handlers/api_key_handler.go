package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"garde/internal/models"
	"garde/internal/repository"
	"garde/pkg/crypto"
	pkgerrors "garde/pkg/errors"
	"garde/pkg/validation"

	"github.com/gin-gonic/gin"
)

// APIKeyHandler manages the per-tenant credentials that authenticate external
// callers of /validate. Every route it serves is superuser-only.
type APIKeyHandler struct {
	repo *repository.RedisRepository
}

func NewAPIKeyHandler(repo *repository.RedisRepository) *APIKeyHandler {
	return &APIKeyHandler{repo: repo}
}

// @Summary List grantable API key scopes
// @Description Returns the closed vocabulary of scopes that may be attached to a per-tenant API key. The UI sources this list rather than hardcoding names, so a new scope is available as soon as the server knows it. Only superuser can perform this operation.
// @Tags Superuser Routes
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Success 200 {object} models.SuccessResponse{data=[]models.APIKeyScopeInfo} "Known scopes"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - superuser access required"
// @Router /admin/api-key-scopes [get]
func (h *APIKeyHandler) ListAPIKeyScopes(c *gin.Context) {
	c.JSON(http.StatusOK, models.NewSuccessResponse(models.AllAPIKeyScopes()))
}

// @Summary Issue a service API key
// @Description Creates a per-tenant API key for calling /validate. client_id names the holder, name labels this key, and scopes must be listed explicitly - there is no default grant. Lifetime is bounded unless never_expires is set: omitting expires_in gives 90 days, and it may not exceed 8760h. The plaintext key is returned once, in this response, and cannot be retrieved again. Only superuser can perform this operation.
// @Tags Superuser Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param request body models.CreateAPIKeyRequest true "Key details"
// @Success 201 {object} models.SuccessResponse{data=models.CreateAPIKeyResponse} "Key issued; plaintext shown once"
// @Failure 400 {object} models.ErrorResponse "Invalid request format"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - superuser access required"
// @Router /admin/api-keys [post]
func (h *APIKeyHandler) CreateAPIKey(c *gin.Context) {
	var req models.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	clientID := strings.TrimSpace(req.ClientID)
	if err := validation.ValidateAPIKeyClientID(clientID); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}

	name := strings.TrimSpace(req.Name)
	if err := validation.ValidateAPIKeyName(name); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}

	// Not defaulted. A credential issued with no stated scopes should grant
	// nothing, and silently granting one is how least privilege erodes.
	if len(req.Scopes) == 0 {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrAPIKeyScopesRequired))
		return
	}
	for _, scope := range req.Scopes {
		if !models.IsKnownAPIKeyScope(scope) {
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidAPIKeyScope))
			return
		}
	}

	expiresAt, errMsg := resolveAPIKeyExpiry(&req, time.Now().UTC())
	if errMsg != "" {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(errMsg))
		return
	}

	if req.RateLimit < 0 {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidAPIKeyRateLimit))
		return
	}

	plaintext, id, secretHash, err := crypto.GenerateAPIKey()
	if err != nil {
		slog.Error("Failed to generate an API key", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	createdBy, _ := contextUserID(c)
	key := &models.ServiceAPIKey{
		ID:         id,
		ClientID:   clientID,
		Name:       name,
		SecretHash: secretHash,
		Scopes:     req.Scopes,
		RateLimit:  req.RateLimit,
		CreatedAt:  time.Now().UTC(),
		CreatedBy:  createdBy,
		ExpiresAt:  expiresAt,
	}

	if err := h.repo.StoreServiceAPIKey(c.Request.Context(), key); err != nil {
		slog.Error("Failed to store an API key", "error", err, "api_key_id", id)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	slog.Info("Issued a service API key",
		"api_key_id", id, "client_id", clientID, "name", name,
		"scopes", req.Scopes, "expires_at", expiresAt, "created_by", createdBy)

	c.JSON(http.StatusCreated, models.NewSuccessResponse(models.CreateAPIKeyResponse{
		APIKeyResponse: models.NewAPIKeyResponse(key),
		Key:            plaintext,
	}))
}

// resolveAPIKeyExpiry turns the request's lifetime fields into an expiry, and
// returns the operator-facing message to answer with when they do not agree.
//
// Omitting expires_in means the default lifetime, not immortality: a key that
// never expires is a key nobody rotates, so that has to be asked for by name.
func resolveAPIKeyExpiry(req *models.CreateAPIKeyRequest, now time.Time) (*time.Time, string) {
	raw := strings.TrimSpace(req.ExpiresIn)

	if req.NeverExpires {
		if raw != "" {
			return nil, pkgerrors.ErrAPIKeyExpiryConflict
		}
		return nil, ""
	}

	ttl := models.DefaultAPIKeyTTL
	if raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			return nil, pkgerrors.ErrInvalidAPIKeyExpiry
		}
		ttl = parsed
	}
	if ttl > models.MaxAPIKeyTTL {
		return nil, pkgerrors.ErrAPIKeyExpiryTooLong
	}

	at := now.Add(ttl)
	return &at, ""
}

// @Summary List service API keys
// @Description Lists issued per-tenant API keys, newest first. Secrets are never returned. Pass client_id to narrow the listing to one holder. Only superuser can perform this operation.
// @Tags Superuser Routes
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param client_id query string false "Only return keys held by this client"
// @Success 200 {object} models.SuccessResponse{data=models.ListAPIKeysResponse} "Issued keys"
// @Failure 400 {object} models.ErrorResponse "Invalid client_id"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - superuser access required"
// @Router /admin/api-keys [get]
func (h *APIKeyHandler) ListAPIKeys(c *gin.Context) {
	var (
		keys []*models.ServiceAPIKey
		err  error
	)

	if clientID := strings.TrimSpace(c.Query("client_id")); clientID != "" {
		if validationErr := validation.ValidateAPIKeyClientID(clientID); validationErr != nil {
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(validationErr.Error()))
			return
		}
		keys, err = h.repo.ListServiceAPIKeysByClient(c.Request.Context(), clientID)
	} else {
		keys, err = h.repo.ListServiceAPIKeys(c.Request.Context())
	}

	if err != nil {
		slog.Error("Failed to list API keys", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	out := make([]models.APIKeyResponse, 0, len(keys))
	for _, key := range keys {
		out = append(out, models.NewAPIKeyResponse(key))
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(models.ListAPIKeysResponse{
		Keys:  out,
		Total: len(out),
	}))
}

// @Summary Revoke a service API key
// @Description Marks a per-tenant API key unusable, effective on its next request. The record is kept so the revocation stays visible. Only superuser can perform this operation.
// @Tags Superuser Routes
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param key_id path string true "API key id"
// @Success 200 {object} models.SuccessResponse{data=models.APIKeyResponse} "Key revoked"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - superuser access required"
// @Failure 404 {object} models.ErrorResponse "Key not found"
// @Router /admin/api-keys/{key_id} [delete]
func (h *APIKeyHandler) RevokeAPIKey(c *gin.Context) {
	keyID := strings.TrimSpace(c.Param("key_id"))
	if keyID == "" {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	key, err := h.repo.RevokeServiceAPIKey(c.Request.Context(), keyID)
	if err != nil {
		if errors.Is(err, repository.ErrAPIKeyNotFound) {
			c.JSON(http.StatusNotFound, models.NewErrorResponse(pkgerrors.ErrAPIKeyNotFound))
			return
		}
		slog.Error("Failed to revoke an API key", "error", err, "api_key_id", keyID)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	revokedBy, _ := contextUserID(c)
	slog.Info("Revoked a service API key",
		"api_key_id", keyID, "client_id", key.ClientID, "name", key.Name, "revoked_by", revokedBy)

	c.JSON(http.StatusOK, models.NewSuccessResponse(models.NewAPIKeyResponse(key)))
}

// @Summary Revoke every API key held by one client
// @Description Revokes all keys issued to a client in one call, for when a holder is compromised and reading the listing to revoke ids by hand would leave live credentials in play. Idempotent: already-revoked keys are reported unchanged. Only superuser can perform this operation.
// @Tags Superuser Routes
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param client_id path string true "Client id whose keys should all be revoked"
// @Success 200 {object} models.SuccessResponse{data=models.RevokeClientKeysResponse} "Keys revoked"
// @Failure 400 {object} models.ErrorResponse "Invalid client_id"
// @Failure 401 {object} models.ErrorResponse "Unauthorized - superuser access required"
// @Failure 404 {object} models.ErrorResponse "Client holds no keys"
// @Router /admin/clients/{client_id}/api-keys [delete]
func (h *APIKeyHandler) RevokeClientAPIKeys(c *gin.Context) {
	clientID := strings.TrimSpace(c.Param("client_id"))
	if err := validation.ValidateAPIKeyClientID(clientID); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}

	revoked, err := h.repo.RevokeServiceAPIKeysByClient(c.Request.Context(), clientID)
	revokedBy, _ := contextUserID(c)

	// Report what was revoked even on a partial failure. During an incident
	// "which ones are dead" is more useful than a bare error, and the keys
	// that did not make it are still live.
	if err != nil {
		slog.Error("Failed to revoke every key for a client",
			"error", err, "client_id", clientID, "revoked", len(revoked), "revoked_by", revokedBy)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	if len(revoked) == 0 {
		c.JSON(http.StatusNotFound, models.NewErrorResponse(pkgerrors.ErrAPIKeyNotFound))
		return
	}

	out := make([]models.APIKeyResponse, 0, len(revoked))
	for _, key := range revoked {
		out = append(out, models.NewAPIKeyResponse(key))
	}

	slog.Info("Revoked every service API key for a client",
		"client_id", clientID, "revoked", len(revoked), "revoked_by", revokedBy)

	c.JSON(http.StatusOK, models.NewSuccessResponse(models.RevokeClientKeysResponse{
		ClientID: clientID,
		Keys:     out,
		Revoked:  len(revoked),
	}))
}
