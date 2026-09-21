package handlers

import (
	"garde/internal/middleware"
	"garde/internal/models"
	"garde/internal/repository"
	"garde/pkg/config"
	"net/http"

	"github.com/gin-gonic/gin"
)

// CaptchaConfigResponse is the public Cap widget config (no secrets).
type CaptchaConfigResponse struct {
	Enabled          bool   `json:"enabled"`
	SiteKey          string `json:"site_key,omitempty"`
	WidgetEndpoint   string `json:"widget_endpoint,omitempty"`
	PublicURL        string `json:"public_url,omitempty"`
	LoginProgressive bool   `json:"login_progressive"`
	LoginRequired    bool   `json:"login_required"`
	RegisterRequired bool   `json:"register_required"`
}

// CaptchaAdminStatusResponse is the superuser Cap status view.
type CaptchaAdminStatusResponse struct {
	Enabled               bool   `json:"enabled"`
	SiteKey               string `json:"site_key,omitempty"`
	PublicURL             string `json:"public_url,omitempty"`
	APIURL                string `json:"api_url,omitempty"`
	WidgetEndpoint        string `json:"widget_endpoint,omitempty"`
	SecretConfigured      bool   `json:"secret_configured"`
	DashboardURL          string `json:"dashboard_url,omitempty"`
	LoginProgressive      bool   `json:"login_progressive"`
	LoginFailureThreshold int64  `json:"login_failure_threshold"`
}

type CaptchaHandler struct {
	repo *repository.Store
}

func NewCaptchaHandler(repo *repository.Store) *CaptchaHandler {
	return &CaptchaHandler{repo: repo}
}

// @Summary Cap captcha public config
// @Description Returns whether Cap is enabled and the widget endpoint. Never includes the secret key.
// @Tags Public Routes
// @Produce json
// @Success 200 {object} models.SuccessResponse{data=CaptchaConfigResponse}
// @Router /captcha/config [get]
func (h *CaptchaHandler) GetConfig(c *gin.Context) {
	enabled := config.CapEnabled()
	resp := CaptchaConfigResponse{
		Enabled:          enabled,
		LoginProgressive: enabled,
		RegisterRequired: enabled,
	}
	if enabled {
		resp.SiteKey = config.CapSiteKey()
		resp.WidgetEndpoint = config.CapWidgetEndpoint()
		resp.PublicURL = config.CapPublicURL()
		// IP-only: show the login widget after a prior failure without leaking email state.
		resp.LoginRequired = middleware.LoginCaptchaRequired(c.Request.Context(), h.repo, "", c.ClientIP())
	}
	c.JSON(http.StatusOK, models.NewSuccessResponse(resp))
}

// @Summary Cap captcha admin status
// @Description Superuser view of Cap configuration (no secret value).
// @Tags Superuser Routes
// @Produce json
// @Security SessionCookie
// @Security Bearer
// @Success 200 {object} models.SuccessResponse{data=CaptchaAdminStatusResponse}
// @Failure 401 {object} models.ErrorResponse
// @Failure 403 {object} models.ErrorResponse
// @Router /admin/captcha [get]
func (h *CaptchaHandler) GetAdminStatus(c *gin.Context) {
	enabled := config.CapEnabled()
	c.JSON(http.StatusOK, models.NewSuccessResponse(CaptchaAdminStatusResponse{
		Enabled:               enabled,
		SiteKey:               config.CapSiteKey(),
		PublicURL:             config.CapPublicURL(),
		APIURL:                config.CapAPIURL(),
		WidgetEndpoint:        config.CapWidgetEndpoint(),
		SecretConfigured:      config.CapSecretKey() != "",
		DashboardURL:          config.CapPublicURL(),
		LoginProgressive:      enabled,
		LoginFailureThreshold: config.CapLoginFailureThreshold,
	}))
}
