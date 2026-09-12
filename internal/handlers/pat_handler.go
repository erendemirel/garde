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

// PATHandler manages personal access tokens a user issues to act as themselves.
type PATHandler struct {
	repo *repository.RedisRepository
}

func NewPATHandler(repo *repository.RedisRepository) *PATHandler {
	return &PATHandler{repo: repo}
}

func requireInteractiveSession(c *gin.Context) bool {
	if _, ok := c.Get("session_id"); !ok {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrSessionRequired))
		return false
	}
	return true
}

// @Summary Issue a personal access token
// @Description Creates a PAT that authenticates as the current user on garde APIs. Requires a browser session (not another PAT). The plaintext is returned once. Lifetime defaults to 90 days unless never_expires is set.
// @Tags User Routes
// @Accept json
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param request body models.CreatePATRequest true "Token details"
// @Success 201 {object} models.SuccessResponse{data=models.CreatePATResponse} "Token issued; plaintext shown once"
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 401 {object} models.ErrorResponse "Unauthorized or session required"
// @Router /users/me/tokens [post]
func (h *PATHandler) CreatePAT(c *gin.Context) {
	if !requireInteractiveSession(c) {
		return
	}

	userID, ok := contextUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrUnauthorized))
		return
	}

	var req models.CreatePATRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	name := strings.TrimSpace(req.Name)
	if err := validation.ValidatePATName(name); err != nil {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(err.Error()))
		return
	}

	expiresAt, errMsg := resolvePATExpiry(&req, time.Now().UTC())
	if errMsg != "" {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(errMsg))
		return
	}

	count, err := h.repo.CountPATsByUser(c.Request.Context(), userID)
	if err != nil {
		slog.Error("Failed to count PATs", "error", err, "user_id", userID)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}
	if count >= models.MaxPATsPerUser {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrPATLimitReached))
		return
	}

	plaintext, id, secretHash, err := crypto.GeneratePAT()
	if err != nil {
		slog.Error("Failed to generate a PAT", "error", err)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	token := &models.PersonalAccessToken{
		ID:         id,
		UserID:     userID,
		Name:       name,
		SecretHash: secretHash,
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  expiresAt,
	}

	if err := h.repo.StorePAT(c.Request.Context(), token); err != nil {
		slog.Error("Failed to store a PAT", "error", err, "pat_id", id, "user_id", userID)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	slog.Info("Issued a personal access token", "pat_id", id, "user_id", userID, "name", name, "expires_at", expiresAt)

	c.JSON(http.StatusCreated, models.NewSuccessResponse(models.CreatePATResponse{
		PATResponse: models.NewPATResponse(token),
		Token:       plaintext,
	}))
}

func resolvePATExpiry(req *models.CreatePATRequest, now time.Time) (*time.Time, string) {
	raw := strings.TrimSpace(req.ExpiresIn)

	if req.NeverExpires {
		if raw != "" {
			return nil, pkgerrors.ErrPATExpiryConflict
		}
		return nil, ""
	}

	ttl := models.DefaultPATTLL
	if raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			return nil, pkgerrors.ErrInvalidPATExpiry
		}
		ttl = parsed
	}
	if ttl > models.MaxPATTLL {
		return nil, pkgerrors.ErrPATExpiryTooLong
	}

	at := now.Add(ttl)
	return &at, ""
}

// @Summary List personal access tokens
// @Description Lists the current user's PATs, newest first. Secrets are never returned. Requires a browser session.
// @Tags User Routes
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Success 200 {object} models.SuccessResponse{data=models.ListPATsResponse} "Issued tokens"
// @Failure 401 {object} models.ErrorResponse "Unauthorized or session required"
// @Router /users/me/tokens [get]
func (h *PATHandler) ListPATs(c *gin.Context) {
	if !requireInteractiveSession(c) {
		return
	}

	userID, ok := contextUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrUnauthorized))
		return
	}

	tokens, err := h.repo.ListPATsByUser(c.Request.Context(), userID)
	if err != nil {
		slog.Error("Failed to list PATs", "error", err, "user_id", userID)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	out := make([]models.PATResponse, 0, len(tokens))
	for _, token := range tokens {
		if token.Revoked() {
			continue
		}
		out = append(out, models.NewPATResponse(token))
	}

	c.JSON(http.StatusOK, models.NewSuccessResponse(models.ListPATsResponse{
		Tokens: out,
		Total:  len(out),
	}))
}

// @Summary Revoke a personal access token
// @Description Marks one of the current user's PATs unusable. Requires a browser session.
// @Tags User Routes
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Param token_id path string true "Token id"
// @Success 200 {object} models.SuccessResponse{data=models.PATResponse} "Token revoked"
// @Failure 401 {object} models.ErrorResponse "Unauthorized or session required"
// @Failure 404 {object} models.ErrorResponse "Token not found"
// @Router /users/me/tokens/{token_id} [delete]
func (h *PATHandler) RevokePAT(c *gin.Context) {
	if !requireInteractiveSession(c) {
		return
	}

	userID, ok := contextUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(pkgerrors.ErrUnauthorized))
		return
	}

	tokenID := strings.TrimSpace(c.Param("token_id"))
	if tokenID == "" {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(pkgerrors.ErrInvalidRequest))
		return
	}

	token, err := h.repo.RevokePAT(c.Request.Context(), tokenID, userID)
	if err != nil {
		if errors.Is(err, repository.ErrPATNotFound) {
			c.JSON(http.StatusNotFound, models.NewErrorResponse(pkgerrors.ErrPATNotFound))
			return
		}
		slog.Error("Failed to revoke a PAT", "error", err, "pat_id", tokenID, "user_id", userID)
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(pkgerrors.ErrOperationFailed))
		return
	}

	slog.Info("Revoked a personal access token", "pat_id", tokenID, "user_id", userID, "name", token.Name)
	c.JSON(http.StatusOK, models.NewSuccessResponse(models.NewPATResponse(token)))
}
