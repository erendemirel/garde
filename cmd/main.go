package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"garde/internal/handlers"
	"garde/internal/middleware"
	"garde/internal/repository"
	"garde/internal/service"
	"garde/pkg/config"
	"garde/pkg/session"
	"garde/pkg/validation"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "garde/endpoint_documentation" // Swagger docs

	"garde/internal/models"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title garde
// @version 1.0
// @description Lightweight and secure authentication service
// @securityDefinitions.apikey ApiKey
// @in header
// @name X-API-Key
// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
// @securityDefinitions.apikey SessionCookie
// @in header
// @name Authorization
// @BasePath /

// Everything the HTTP surfaces need. Both listeners serve the same objects;
// only the routes they mount and the certificates they demand differ.
type routerDeps struct {
	repo             *repository.Store
	authService      *service.AuthService
	securityAnalyzer *service.SecurityAnalyzer
	authHandler      *handlers.AuthHandler
	apiKeyHandler    *handlers.APIKeyHandler
	patHandler       *handlers.PATHandler
	rateLimiter      *middleware.RateLimiter
}

func main() {
	// Initialize config loader (reads from /run/secrets - should be tmpfs)
	if err := config.Init(""); err != nil {
		fmt.Printf("Failed to initialize config: %v\n", err)
		fmt.Println("Ensure secrets directory exists at /run/secrets with required secret files")
		os.Exit(1)
	}

	// Start watching for secret changes (hot-reload)
	if err := config.StartWatcher(); err != nil {
		slog.Warn("Failed to start config watcher, hot-reload disabled", "error", err)
	}

	session.InitRapidRequestConfig()

	// Initialize logger
	logLevel := slog.LevelInfo

	// Set log level
	envLogLevel := strings.ToUpper(config.Get("LOG_LEVEL"))
	switch envLogLevel {
	case "DEBUG":
		logLevel = slog.LevelDebug
	case "INFO":
		logLevel = slog.LevelInfo
	case "WARN":
		logLevel = slog.LevelWarn
	case "ERROR":
		logLevel = slog.LevelError
	}

	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	})
	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	slog.Info("Logger initialized", "level", envLogLevel)

	if err := validation.ValidateConfig(); err != nil {
		slog.Error("Configuration validation failed", "error", err)
		os.Exit(1)
	}
	applyGinMode()

	slog.Info("Connecting to PostgreSQL and Redis...")
	repo, err := repository.NewStore()
	if err != nil {
		slog.Error("Failed to connect to the data stores", "error", err)
		os.Exit(1)
	}
	slog.Info("Connected to the data stores successfully")

	// The permission catalogue shares the durable pool the store just opened.
	if err := service.InitPermissionRepository(repo.DB()); err != nil {
		slog.Error("Failed to initialize permission repository", "error", err)
		slog.Info("Running without permissions/groups system")
	}

	// Initialize superuser
	if err := service.InitializeSuperUser(context.Background(), repo); err != nil {
		slog.Error("Failed to initialize superuser", "error", err)
		os.Exit(1)
	}

	// Initialize admins
	if err := service.InitializeAdminUsers(context.Background(), repo); err != nil {
		slog.Error("Failed to initialize admin users", "error", err)
		os.Exit(1)
	}

	// Reject hot-reloads that would install invalid secrets (e.g. weak passwords),
	// then re-dial storage and refresh bootstrap accounts.
	config.SetReloadValidator(validation.ValidateConfig)
	config.SetReloadHook(func() {
		applyGinMode()

		slog.Info("Secrets changed, reconnecting storage backends...")
		if err := repo.Reconnect(); err != nil {
			slog.Error("Failed to reconnect after secret change", "error", err)
			return
		}

		// Refresh superuser credentials after secrets change
		if err := service.InitializeSuperUser(context.Background(), repo); err != nil {
			slog.Error("Failed to refresh superuser after secret change", "error", err)
		}

		// Refresh admin users after secrets change
		if err := service.InitializeAdminUsers(context.Background(), repo); err != nil {
			slog.Error("Failed to refresh admin users after secret change", "error", err)
		}
	})

	authService := service.NewAuthService(repo)
	deps := &routerDeps{
		repo:             repo,
		authService:      authService,
		securityAnalyzer: service.NewSecurityAnalyzer(repo),
		authHandler:      handlers.NewAuthHandler(authService),
		apiKeyHandler:    handlers.NewAPIKeyHandler(repo),
		patHandler:       handlers.NewPATHandler(repo),
		rateLimiter:      middleware.NewRateLimiter(repo),
	}

	router := newEngine(deps)
	mountPublicRoutes(router, deps)

	// /validate answers on the public listener only when nothing more private
	// is carrying it. A service endpoint that can validate any user's session
	// does not belong on the hostname browsers reach.
	if config.PublicValidateEnabled() {
		opts := validateRouteOptions{mtls: config.PublicValidateMTLS()}
		mountValidateRoute(router, deps, opts)
		slog.Info("/validate mounted on the public listener",
			"mtls", opts.mtls.String(), "credentials", "per-caller keys only")
	} else {
		slog.Info("/validate is not served on the public listener")
	}

	// Swagger — opt-in via ENABLE_SWAGGER (off by default)
	if config.GetBool("ENABLE_SWAGGER") {
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		slog.Info("Swagger UI enabled at /swagger/index.html")
	}

	servers := make([]*http.Server, 0, 2)

	publicSrv, err := newPublicServer(router)
	if err != nil {
		slog.Error("Failed to configure the public listener", "error", err)
		os.Exit(1)
	}
	servers = append(servers, publicSrv)

	if config.ServiceListenerEnabled() {
		serviceSrv, err := newServiceServer(deps)
		if err != nil {
			slog.Error("Failed to configure the service listener", "error", err)
			os.Exit(1)
		}
		servers = append(servers, serviceSrv)
	}

	for _, srv := range servers {
		go serve(srv)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	slog.Info("Shutting down server", "signal", sig.String())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	failed := false
	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("Server forced to shutdown", "addr", srv.Addr, "error", err)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
	slog.Info("Server stopped")
}

// newEngine builds the middleware stack both listeners share. /health is
// registered before the rate limiter so probes are never throttled.
func newEngine(deps *routerDeps) *gin.Engine {
	router := gin.New()
	// Do not trust X-Forwarded-For unless TRUSTED_PROXIES is set (comma-separated CIDRs/IPs).
	// Gin's default trusts all proxies, which allows ClientIP spoofing.
	if trusted := strings.TrimSpace(config.Get("TRUSTED_PROXIES")); trusted != "" {
		proxies := make([]string, 0)
		for _, p := range strings.Split(trusted, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				proxies = append(proxies, p)
			}
		}
		if err := router.SetTrustedProxies(proxies); err != nil {
			slog.Error("Invalid TRUSTED_PROXIES", "error", err)
			os.Exit(1)
		}
		slog.Info("Trusted proxies configured", "count", len(proxies))
	} else if err := router.SetTrustedProxies(nil); err != nil {
		slog.Error("Failed to disable trusted proxies", "error", err)
		os.Exit(1)
	}

	router.Use(middleware.Recovery()) // Recovery middleware (to not to expose error details during panic)
	router.Use(gin.Logger())

	router.Use(middleware.CORSMiddleware())

	// Security headers middleware with strict CSP
	router.Use(func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		if config.GetBool("USE_TLS") {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Relaxed CSP only for Swagger UI
		if strings.HasPrefix(c.Request.URL.Path, "/swagger/") {
			c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		} else {
			c.Header("Content-Security-Policy", "default-src 'self'")
		}
		c.Next()
	})

	router.Use(middleware.LimitBodySize(validation.MaxBodySize))

	router.Use(middleware.ValidateRequestParameters())

	// Probes run before the rate limiter so load balancers are never throttled.
	// /live  — process is up (do not check backends; used for restart loops)
	// /ready — node can serve traffic (Postgres + Redis)
	// /health — alias of /ready for older LB configs
	router.GET("/live", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	ready := func(c *gin.Context) {
		ctx := c.Request.Context()
		if err := deps.repo.PingPostgres(ctx); err != nil {
			slog.Warn("Readiness check failed", "backend", "postgres", "error", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable", "backend": "postgres"})
			return
		}
		if err := deps.repo.PingRedis(ctx); err != nil {
			slog.Warn("Readiness check failed", "backend", "redis", "error", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable", "backend": "redis"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
	router.GET("/ready", ready)
	router.GET("/health", ready)

	router.Use(deps.rateLimiter.Limit())

	return router
}

// mountPublicRoutes registers everything browsers and API clients use. None of
// it requires a client certificate.
func mountPublicRoutes(router *gin.Engine, deps *routerDeps) {
	authHandler := deps.authHandler

	public := router.Group("")
	public.Use(middleware.SecurityMiddleware(deps.securityAnalyzer))
	{
		public.POST("/login", authHandler.Login)
		public.POST("/users", authHandler.CreateUser)
		public.POST("/users/password/otp", authHandler.RequestOTP)
		public.POST("/users/password/reset", authHandler.ResetPassword)
	}

	// Regular protected routes (no mTLS or admin login required)
	protected := router.Group("")
	protected.Use(middleware.AuthMiddleware(deps.authService, deps.securityAnalyzer, deps.repo))
	protected.Use(middleware.CookieCSRFMiddleware())
	protected.Use(deps.rateLimiter.LimitByUser())
	{
		protected.GET("/users/me", authHandler.GetCurrentUser)
		protected.POST("/logout", authHandler.Logout)
		protected.POST("/users/password/change", authHandler.ChangePassword)
		protected.POST("/users/mfa/setup", authHandler.SetupMFA)
		protected.POST("/users/mfa/verify", authHandler.VerifyAndEnableMFA)
		protected.POST("/users/mfa/disable", authHandler.DisableMFA)
		protected.POST("/users/request-update-from-admin", authHandler.RequestUpdate)
		protected.GET("/permissions", authHandler.ListPermissions)
		protected.GET("/groups", authHandler.ListGroups)
		protected.POST("/users/me/tokens", deps.patHandler.CreatePAT)
		protected.GET("/users/me/tokens", deps.patHandler.ListPATs)
		protected.DELETE("/users/me/tokens/:token_id", deps.patHandler.RevokePAT)
	}

	// Admin-only endpoints (require admin login, but no mTLS)
	// AuthMiddleware runs first to set is_admin/is_superuser flags
	// AdminMiddleware then checks those flags and blocks non-admins
	adminProtected := router.Group("")
	adminProtected.Use(middleware.AuthMiddleware(deps.authService, deps.securityAnalyzer, deps.repo))
	adminProtected.Use(middleware.CookieCSRFMiddleware())
	adminProtected.Use(middleware.AdminMiddleware(deps.authService))
	adminProtected.Use(deps.rateLimiter.LimitByUser())
	// RequireAdminScope is per route, not on the group, because separating
	// these five is the whole point: an admin listed in ADMIN_SCOPES_JSON can
	// be given reading and updating without deletion. An admin with no entry
	// keeps all five, as before.
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

	// Superuser-only endpoints (require superuser login)
	// AuthMiddleware runs first to set is_superuser flag
	// SuperuserMiddleware then checks that flag and blocks non-superusers
	superuserProtected := router.Group("")
	superuserProtected.Use(middleware.AuthMiddleware(deps.authService, deps.securityAnalyzer, deps.repo))
	superuserProtected.Use(middleware.CookieCSRFMiddleware())
	superuserProtected.Use(middleware.SuperuserMiddleware())
	superuserProtected.Use(deps.rateLimiter.LimitByUser())
	{
		// Permission management
		superuserProtected.POST("/admin/permissions", authHandler.CreatePermission)
		superuserProtected.PUT("/admin/permissions/:permission_name", authHandler.UpdatePermission)
		superuserProtected.DELETE("/admin/permissions/:permission_name", authHandler.DeletePermission)

		// Group management
		superuserProtected.POST("/admin/groups", authHandler.CreateGroup)
		superuserProtected.PUT("/admin/groups/:group_name", authHandler.UpdateGroup)
		superuserProtected.DELETE("/admin/groups/:group_name", authHandler.DeleteGroup)

		// Permission visibility management
		superuserProtected.GET("/admin/permissions/visibility", authHandler.GetAllPermissionVisibility)
		superuserProtected.POST("/admin/permissions/visibility", authHandler.AddPermissionVisibility)
		superuserProtected.DELETE("/admin/permissions/visibility", authHandler.RemovePermissionVisibility)

		// Admin-user management mapping
		superuserProtected.GET("/admin/users/management", authHandler.GetAdminUserManagement)

		// Per-tenant credentials for external callers of /validate
		superuserProtected.GET("/admin/api-key-scopes", deps.apiKeyHandler.ListAPIKeyScopes)
		superuserProtected.POST("/admin/api-keys", deps.apiKeyHandler.CreateAPIKey)
		superuserProtected.GET("/admin/api-keys", deps.apiKeyHandler.ListAPIKeys)
		superuserProtected.DELETE("/admin/api-keys/:key_id", deps.apiKeyHandler.RevokeAPIKey)
		superuserProtected.DELETE("/admin/tenants/:tenant_id/api-keys", deps.apiKeyHandler.RevokeTenantAPIKeys)
	}
}

// validateRouteOptions describes how one listener authenticates /validate.
type validateRouteOptions struct {
	// mtls requires a verified client certificate when it is required.
	mtls config.ClientCertPolicy
}

// mountValidateRoute registers the service session-validation endpoint.
//
// No cookie/Bearer AuthMiddleware — callers pass the session via X-Session-ID.
// An issued per-caller API key is always required; the client certificate is
// required whenever the listener carrying this route was built to verify one.
func mountValidateRoute(router *gin.Engine, deps *routerDeps, opts validateRouteOptions) {
	validateEndpoint := router.Group("/validate")

	if opts.mtls == config.ClientCertRequired {
		validateEndpoint.Use(middleware.MTLSMiddleware())
	}

	validateEndpoint.Use(middleware.APIKeyAuth(middleware.APIKeyAuthOptions{
		Repo:          deps.repo,
		RequiredScope: models.ScopeValidate,
	}))

	// Charges the request to the calling key rather than to its address,
	// so that callers sharing one NAT do not share one budget.
	validateEndpoint.Use(deps.rateLimiter.LimitByAPIKey())

	validateEndpoint.GET("", deps.authHandler.ValidateSession)
}

// newPublicServer builds the listener browsers and API clients reach. Its
// client-certificate policy defaults to off, because a public listener that
// demands certificates cannot serve a login page.
func newPublicServer(handler http.Handler) (*http.Server, error) {
	port := config.GetWithDefault("PORT", "8443")
	srv := newHTTPServer(":"+port, handler)

	if !config.GetBool("USE_TLS") {
		slog.Warn("Starting public listener without TLS", "port", port)
		return srv, nil
	}

	tlsConfig, err := buildTLSConfig(
		config.Get("TLS_CERT_PATH"),
		config.Get("TLS_KEY_PATH"),
		strings.TrimSpace(config.Get("TLS_CA_PATH")),
		config.BrowserMTLS(),
		"public",
	)
	if err != nil {
		return nil, err
	}
	srv.TLSConfig = tlsConfig

	slog.Info("Starting public listener with TLS", "port", port, "browser_mtls", config.BrowserMTLS().String())
	return srv, nil
}

// newServiceServer builds the private listener that carries /validate. It is
// always TLS: the point of moving the endpoint here is that service calls can
// be authenticated by certificate, which is impossible over plaintext.
func newServiceServer(deps *routerDeps) (*http.Server, error) {
	policy := config.ServiceMTLS()
	router := newEngine(deps)
	// Mesh callers present a client certificate and an issued per-caller key.
	mountValidateRoute(router, deps, validateRouteOptions{mtls: policy})

	tlsConfig, err := buildTLSConfig(
		config.ServiceTLSCertPath(),
		config.ServiceTLSKeyPath(),
		config.ServiceTLSCAPath(),
		policy,
		"service",
	)
	if err != nil {
		return nil, err
	}

	port := config.ServicePort()
	srv := newHTTPServer(config.ServiceBind()+":"+port, router)
	srv.TLSConfig = tlsConfig

	if policy != config.ClientCertRequired {
		slog.Warn("Service listener does not require client certificates — keep it on a private network",
			"port", port)
	}
	slog.Info("Starting service listener with TLS", "port", port, "service_mtls", policy.String())
	return srv, nil
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// buildTLSConfig loads the server keypair and maps a client-certificate policy
// onto the handshake.
//
// "Off" is not the same as "no client CA". When a CA is configured, a
// certificate that is presented is still verified — that is what allows
// /validate to demand mTLS while browsers on the same listener present
// nothing.
func buildTLSConfig(certPath, keyPath, caPath string, policy config.ClientCertPolicy, surface string) (*tls.Config, error) {
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("%s listener needs both a certificate and a key path", surface)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load the %s server certificate: %w", surface, err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
	}

	if caPath != "" {
		caCertPool := x509.NewCertPool()
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read the %s client CA: %w", surface, err)
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("no usable certificate in the %s client CA at %s", surface, caPath)
		}

		if block, _ := pem.Decode(caCert); block != nil {
			if parsed, err := x509.ParseCertificate(block.Bytes); err == nil {
				slog.Info("Loaded client CA", "surface", surface, "subject", parsed.Subject, "issuer", parsed.Issuer)
			}
		}

		tlsConfig.ClientCAs = caCertPool
		if policy == config.ClientCertRequired {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			// Verify client certs when presented; do not require them on every
			// connection.
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
	} else if policy != config.ClientCertOff {
		return nil, fmt.Errorf("%s listener asks for client certificates but no client CA is configured", surface)
	}

	if len(cert.Certificate) > 0 {
		if x509Cert, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			slog.Info("Server using certificate", "surface", surface, "subject", x509Cert.Subject, "issuer", x509Cert.Issuer)
		}
	}

	return tlsConfig, nil
}

func serve(srv *http.Server) {
	var err error
	if srv.TLSConfig != nil {
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		slog.Error("Failed to start server", "addr", srv.Addr, "error", err)
		os.Exit(1)
	}
}

// applyGinMode maps the GIN_MODE secret onto gin's runtime mode. Gin only
// reads the GIN_MODE environment variable at import time, so secrets rendered
// under /run/secrets would otherwise be ignored and leave the process in debug.
func applyGinMode() {
	mode := strings.ToLower(strings.TrimSpace(config.Get("GIN_MODE")))
	switch mode {
	case gin.ReleaseMode:
		gin.SetMode(gin.ReleaseMode)
	case gin.TestMode:
		gin.SetMode(gin.TestMode)
	case gin.DebugMode, "":
		gin.SetMode(gin.DebugMode)
	default:
		slog.Warn("Invalid GIN_MODE, using release", "value", mode)
		gin.SetMode(gin.ReleaseMode)
	}
	slog.Info("Gin mode applied", "mode", gin.Mode())
}
