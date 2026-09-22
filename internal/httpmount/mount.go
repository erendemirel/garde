// Package httpmount registers HTTP routes on the public and service listeners.
package httpmount

import (
	"log/slog"

	"garde/internal/handlers"
	"garde/internal/middleware"
	"garde/internal/models"
	"garde/internal/repository"
	"garde/internal/service"
	"garde/pkg/config"

	"github.com/gin-gonic/gin"
)

// Context key for which listener accepted the request.
const ContextKeySurface = "request_surface"

const (
	SurfaceExternal = "external" // public listener
	SurfaceInternal = "internal" // service listener
)

// Deps is everything route mounts need from main.
type Deps struct {
	Repo             *repository.Store
	AuthService      *service.AuthService
	SecurityAnalyzer *service.SecurityAnalyzer
	AuthHandler      *handlers.AuthHandler
	APIKeyHandler    *handlers.APIKeyHandler
	PATHandler       *handlers.PATHandler
	CaptchaHandler   *handlers.CaptchaHandler
	RateLimiter      *middleware.RateLimiter
}

// MarkSurface stamps every request with external or internal.
func MarkSurface(surface string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(ContextKeySurface, surface)
		c.Next()
	}
}

// MountPublicConfig exposes kill-switch / registration gates (safe on any listener).
func MountPublicConfig(router *gin.Engine) {
	router.GET("/public/config", handlers.GetPublicConfig)
}

// MountUnauthenticatedAuth is login + register + password reset + email verify + captcha.
func MountUnauthenticatedAuth(router *gin.Engine, deps *Deps) {
	router.GET("/captcha/config", deps.CaptchaHandler.GetConfig)

	g := router.Group("")
	g.Use(middleware.SecurityMiddleware(deps.SecurityAnalyzer))
	g.Use(middleware.CapMiddleware(deps.Repo))
	{
		g.POST("/login", deps.AuthHandler.Login)
		g.POST("/users", deps.AuthHandler.CreateUser)
		g.POST("/users/password/otp", deps.AuthHandler.RequestOTP)
		g.POST("/users/password/reset", deps.AuthHandler.ResetPassword)
		g.POST("/users/email/verify", deps.AuthHandler.VerifyEmail)
		g.POST("/users/email/verify/resend", deps.AuthHandler.ResendVerifyEmail)
	}
}

// MountUserProtected is session-authenticated self-service (not admin).
func MountUserProtected(router *gin.Engine, deps *Deps) {
	g := router.Group("")
	g.Use(middleware.AuthMiddleware(deps.AuthService, deps.SecurityAnalyzer, deps.Repo))
	g.Use(middleware.CookieCSRFMiddleware())
	g.Use(deps.RateLimiter.LimitByUser())
	{
		g.GET("/users/me", deps.AuthHandler.GetCurrentUser)
		g.POST("/logout", deps.AuthHandler.Logout)
		g.GET("/users/me/sessions", deps.AuthHandler.ListSessions)
		g.POST("/users/me/sessions/revoke-others", deps.AuthHandler.RevokeOtherSessions)
		g.POST("/users/me/sessions/:session_id/revoke", deps.AuthHandler.RevokeOwnSession)
		g.POST("/users/password/change", deps.AuthHandler.ChangePassword)
		g.POST("/users/mfa/setup", deps.AuthHandler.SetupMFA)
		g.POST("/users/mfa/verify", deps.AuthHandler.VerifyAndEnableMFA)
		g.POST("/users/mfa/disable", deps.AuthHandler.DisableMFA)
		g.POST("/users/request-update-from-admin", deps.AuthHandler.RequestUpdate)
		g.GET("/permissions", deps.AuthHandler.ListPermissions)
		g.GET("/groups", deps.AuthHandler.ListGroups)
		g.POST("/users/me/tokens", deps.PATHandler.CreatePAT)
		g.GET("/users/me/tokens", deps.PATHandler.ListPATs)
		g.DELETE("/users/me/tokens/:token_id", deps.PATHandler.RevokePAT)
	}
}

// MountAdminAndSuperuser is always intended for the internal (service) listener.
func MountAdminAndSuperuser(router *gin.Engine, deps *Deps) {
	authHandler := deps.AuthHandler

	adminProtected := router.Group("")
	adminProtected.Use(middleware.AuthMiddleware(deps.AuthService, deps.SecurityAnalyzer, deps.Repo))
	adminProtected.Use(middleware.CookieCSRFMiddleware())
	adminProtected.Use(middleware.AdminMiddleware(deps.AuthService))
	adminProtected.Use(deps.RateLimiter.LimitByUser())
	{
		adminProtected.GET("/users",
			middleware.RequireAdminScope(config.ScopeAdminUsersRead), authHandler.ListUsers)
		adminProtected.GET("/users/:user_id",
			middleware.RequireAdminScope(config.ScopeAdminUsersRead), authHandler.GetUser)
		adminProtected.PUT("/users/:user_id",
			middleware.RequireAdminScope(config.ScopeAdminUsersWrite), authHandler.UpdateUser)
		adminProtected.DELETE("/users/:user_id",
			middleware.RequireAdminScope(config.ScopeAdminUsersDelete), authHandler.DeleteUser)
		adminProtected.POST("/sessions/revoke",
			middleware.RequireAdminScope(config.ScopeAdminSessionsRevoke), authHandler.RevokeUserSession)
	}

	superuserProtected := router.Group("")
	superuserProtected.Use(middleware.AuthMiddleware(deps.AuthService, deps.SecurityAnalyzer, deps.Repo))
	superuserProtected.Use(middleware.CookieCSRFMiddleware())
	superuserProtected.Use(middleware.SuperuserMiddleware())
	superuserProtected.Use(deps.RateLimiter.LimitByUser())
	{
		superuserProtected.POST("/admin/permissions", authHandler.CreatePermission)
		superuserProtected.PUT("/admin/permissions/:permission_name", authHandler.UpdatePermission)
		superuserProtected.DELETE("/admin/permissions/:permission_name", authHandler.DeletePermission)
		superuserProtected.POST("/admin/groups", authHandler.CreateGroup)
		superuserProtected.PUT("/admin/groups/:group_name", authHandler.UpdateGroup)
		superuserProtected.DELETE("/admin/groups/:group_name", authHandler.DeleteGroup)
		superuserProtected.GET("/admin/permissions/visibility", authHandler.GetAllPermissionVisibility)
		superuserProtected.POST("/admin/permissions/visibility", authHandler.AddPermissionVisibility)
		superuserProtected.DELETE("/admin/permissions/visibility", authHandler.RemovePermissionVisibility)
		superuserProtected.GET("/admin/users/management", authHandler.GetAdminUserManagement)
		superuserProtected.GET("/admin/api-key-scopes", deps.APIKeyHandler.ListAPIKeyScopes)
		superuserProtected.POST("/admin/api-keys", deps.APIKeyHandler.CreateAPIKey)
		superuserProtected.GET("/admin/api-keys", deps.APIKeyHandler.ListAPIKeys)
		superuserProtected.DELETE("/admin/api-keys/:key_id", deps.APIKeyHandler.RevokeAPIKey)
		superuserProtected.DELETE("/admin/tenants/:tenant_id/api-keys", deps.APIKeyHandler.RevokeTenantAPIKeys)
		superuserProtected.GET("/admin/captcha", deps.CaptchaHandler.GetAdminStatus)
	}
}

// ValidateOpts configures /validate on one listener.
type ValidateOpts struct {
	MTLS     config.ClientCertPolicy
	Audience string
}

// MountValidate registers session validation for machine callers.
func MountValidate(router *gin.Engine, deps *Deps, opts ValidateOpts) {
	g := router.Group("/validate")
	if opts.MTLS == config.ClientCertRequired {
		g.Use(middleware.MTLSMiddleware())
	}
	g.Use(middleware.APIKeyAuth(middleware.APIKeyAuthOptions{
		Repo:             deps.Repo,
		RequiredScope:    models.ScopeValidate,
		RequiredAudience: opts.Audience,
	}))
	g.Use(deps.RateLimiter.LimitByAPIKey())
	g.GET("", deps.AuthHandler.ValidateSession)
}

// MountPublicListener applies the public (external) surface.
//
// Kill switch on (PUBLIC_SELF_SERVICE=false): only /public/config (probes live
// on the engine). Kill switch off: unauthenticated auth + user self-service;
// optional public /validate. Admin/superuser never mount here when the service
// listener is enabled.
func MountPublicListener(router *gin.Engine, deps *Deps) {
	router.Use(MarkSurface(SurfaceExternal))
	MountPublicConfig(router)

	if !config.PublicSelfServiceEnabled() {
		slog.Info("Public kill switch on — public listener serves only /public/config (+ probes)")
		return
	}

	MountUnauthenticatedAuth(router, deps)
	MountUserProtected(router, deps)

	if config.PublicValidateEnabled() {
		opts := ValidateOpts{MTLS: config.PublicValidateMTLS()}
		if config.ServiceListenerEnabled() {
			opts.Audience = models.AudienceTenant
		}
		MountValidate(router, deps, opts)
		slog.Info("/validate mounted on the public listener",
			"mtls", opts.MTLS.String(),
			"audience", audienceLabel(opts.Audience))
	}

	// Single-listener compat: admin must live somewhere. Prefer SERVICE_LISTENER.
	if !config.ServiceListenerEnabled() {
		slog.Warn("SERVICE_LISTENER is off — mounting admin/superuser on the public listener (enable the service listener for internal-only admin)")
		MountAdminAndSuperuser(router, deps)
	}
}

// MountServiceListener applies the internal surface: /validate, admin/superuser,
// and (when the public kill switch is on) the full user auth surface.
func MountServiceListener(router *gin.Engine, deps *Deps) {
	router.Use(MarkSurface(SurfaceInternal))
	MountPublicConfig(router) // handy for private operators

	MountValidate(router, deps, ValidateOpts{
		MTLS:     config.ServiceMTLS(),
		Audience: models.AudienceInternal,
	})
	MountAdminAndSuperuser(router, deps)

	if !config.PublicSelfServiceEnabled() {
		MountUnauthenticatedAuth(router, deps)
		MountUserProtected(router, deps)
		slog.Info("Public kill switch on — full user auth surface mounted on the service listener")
	}
}

func audienceLabel(audience string) string {
	if audience == "" {
		return "any"
	}
	return audience
}
