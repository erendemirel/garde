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
	"garde/pkg/errors"
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

	// Initialize permission repository (SQLite based in Memory I/O mode)
	if err := service.InitPermissionRepository(); err != nil {
		slog.Error("Failed to initialize permission repository", "error", err)
		slog.Info("Running without permissions/groups system")
	}

	if err := validation.ValidateConfig(); err != nil {
		slog.Error("Configuration validation failed", "error", err)
		os.Exit(1)
	}

	var repo *repository.RedisRepository
	var err error

	slog.Info("Connecting to Redis...")
	repo, err = repository.NewRedisRepository()
	if err != nil {
		slog.Error("Failed to connect to Redis", "error", err)
		os.Exit(1)
	}
	slog.Info("Connected to Redis successfully")

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

	// Set up hot-reload: reconnect Redis when secrets change
	config.SetReloadHook(func() {
		slog.Info("Secrets changed, reconnecting to Redis...")
		if err := repo.Reconnect(); err != nil {
			slog.Error("Failed to reconnect to Redis after secret change", "error", err)
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
	securityAnalyzer := service.NewSecurityAnalyzer(repo)
	authHandler := handlers.NewAuthHandler(authService)

	rateLimiter := middleware.NewRateLimiter(repo)

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

	// Liveness/readiness — before rate limiting so probes are not throttled
	router.GET("/health", func(c *gin.Context) {
		if err := repo.Ping(c.Request.Context()); err != nil {
			slog.Warn("Health check failed", "error", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	router.Use(rateLimiter.Limit())

	public := router.Group("")
	public.Use(middleware.SecurityMiddleware(securityAnalyzer))
	{
		public.POST("/login", authHandler.Login)
		public.POST("/users", authHandler.CreateUser)
		public.POST("/users/password/otp", authHandler.RequestOTP)
		public.POST("/users/password/reset", authHandler.ResetPassword)
	}

	// Regular protected routes (no mTLS or admin login required)
	protected := router.Group("")
	protected.Use(middleware.AuthMiddleware(authService, securityAnalyzer))
	protected.Use(rateLimiter.LimitByUser())
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
	}

	// Admin-only endpoints (require admin login, but no mTLS)
	// AuthMiddleware runs first to set is_admin/is_superuser flags
	// AdminMiddleware then checks those flags and blocks non-admins
	adminProtected := router.Group("")
	adminProtected.Use(middleware.AuthMiddleware(authService, securityAnalyzer))
	adminProtected.Use(middleware.AdminMiddleware(authService))
	adminProtected.Use(rateLimiter.LimitByUser())
	{
		adminProtected.GET("/users", authHandler.ListUsers)
		adminProtected.GET("/users/:user_id", authHandler.GetUser)
		adminProtected.PUT("/users/:user_id", authHandler.UpdateUser)
		adminProtected.DELETE("/users/:user_id", authHandler.DeleteUser)
		adminProtected.POST("/sessions/revoke", authHandler.RevokeUserSession)
	}

	// Superuser-only endpoints (require superuser login)
	// AuthMiddleware runs first to set is_superuser flag
	// SuperuserMiddleware then checks that flag and blocks non-superusers
	superuserProtected := router.Group("")
	superuserProtected.Use(middleware.AuthMiddleware(authService, securityAnalyzer))
	superuserProtected.Use(middleware.SuperuserMiddleware())
	superuserProtected.Use(rateLimiter.LimitByUser())
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

		// Group-user and admin-user management mappings
		superuserProtected.GET("/admin/groups/users", authHandler.GetAllGroupUsers)
		superuserProtected.GET("/admin/users/management", authHandler.GetAdminUserManagement)
	}

	// /validate: API key (+ mTLS when built-in TLS and a client CA are configured).
	// No cookie/Bearer AuthMiddleware — services pass session_id as a query param.
	validateEndpoint := router.Group("/validate")
	validateEndpoint.Use(func(c *gin.Context) {
		useTLS := config.GetBool("USE_TLS")
		caPath := strings.TrimSpace(config.Get("TLS_CA_PATH"))
		if useTLS && caPath != "" {
			middleware.MTLSMiddleware()(c)
			if c.IsAborted() {
				return
			}
		}

		apiKey := c.GetHeader(middleware.APIKeyHeader)
		if apiKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}
		middleware.APIKeyMiddleware()(c)
	})
	validateEndpoint.GET("", authHandler.ValidateSession)

	// Swagger — opt-in via ENABLE_SWAGGER (off by default)
	if config.GetBool("ENABLE_SWAGGER") {
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		slog.Info("Swagger UI enabled at /swagger/index.html")
	}

	var srv *http.Server
	port := config.GetWithDefault("PORT", "8443")
	useTLS := config.GetBool("USE_TLS")

	// Built-in server TLS. Client certs are optional at the handshake so browsers
	// can use cookie auth; /validate enforces mTLS in middleware when a CA is set.
	if useTLS {

		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.NoClientCert,
		}

		cert, err := tls.LoadX509KeyPair(config.Get("TLS_CERT_PATH"), config.Get("TLS_KEY_PATH"))
		if err != nil {
			slog.Error("Failed to load server certificate", "error", err)
			os.Exit(1)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		if caPath := config.Get("TLS_CA_PATH"); caPath != "" {
			caCertPool := x509.NewCertPool()
			caCert, err := os.ReadFile(caPath)
			if err != nil {
				slog.Error("Failed to read CA certificate", "error", err)
				os.Exit(1)
			}
			if !caCertPool.AppendCertsFromPEM(caCert) {
				slog.Error("Failed to append CA certificate")
				os.Exit(1)
			}

			block, _ := pem.Decode(caCert)
			if block != nil {
				parsed, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					slog.Info("Server loaded CA cert", "subject", parsed.Subject, "issuer", parsed.Issuer)
				}
			}

			tlsConfig.ClientCAs = caCertPool
			// Verify client certs when presented; do not require them on every connection.
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
			slog.Info("Loaded CA certificates — client certs verified when presented (required on /validate)")
		} else {
			slog.Warn("No TLS_CA_PATH — /validate will not require mTLS")
		}

		if len(cert.Certificate) > 0 {
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				slog.Info("Server using certificate", "subject", x509Cert.Subject, "issuer", x509Cert.Issuer)
			}
		}

		srv = &http.Server{
			Addr:      ":" + port,
			Handler:   router,
			TLSConfig: tlsConfig,
		}

		slog.Info("Starting server with TLS", "port", port)
		go func() {
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				slog.Error("Failed to start server", "error", err)
				os.Exit(1)
			}
		}()
	} else {
		srv = &http.Server{
			Addr:    ":" + port,
			Handler: router,
		}

		slog.Warn("Starting server without TLS", "port", port)
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("Failed to start server", "error", err)
				os.Exit(1)
			}
		}()
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	slog.Info("Shutting down server", "signal", sig.String())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}
	slog.Info("Server stopped")
}
