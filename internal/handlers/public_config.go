package handlers

import (
	"garde/internal/models"
	"garde/pkg/config"
	"net/http"

	"github.com/gin-gonic/gin"
)

// PublicConfigResponse is the browser-facing registration/auth surface config
// (no secrets). Used so the UI can hide register/forgot-password and tailor
// post-register copy without guessing Vault settings.
type PublicConfigResponse struct {
	PublicSelfService         bool   `json:"public_self_service"`
	RequireAdminApproval      bool   `json:"require_admin_approval"`
	RequireEmailVerification  bool   `json:"require_email_verification"`
	EmailVerificationCoerced  bool   `json:"email_verification_coerced"`
	RegistrationNext          string `json:"registration_next"`
}

// @Summary Public auth configuration
// @Description Returns whether public auth (login + self-service) is enabled and which registration gates apply.
// @Tags Public Routes
// @Produce json
// @Success 200 {object} models.SuccessResponse{data=PublicConfigResponse}
// @Router /public/config [get]
func GetPublicConfig(c *gin.Context) {
	c.JSON(http.StatusOK, models.NewSuccessResponse(PublicConfigResponse{
		PublicSelfService:        config.PublicSelfServiceEnabled(),
		RequireAdminApproval:     config.RequireAdminApproval(),
		RequireEmailVerification: config.RequireEmailVerification(),
		EmailVerificationCoerced: config.EmailVerificationCoerced(),
		RegistrationNext:         config.RegistrationNextStep(),
	}))
}
