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
	"garde/pkg/errors"
	"garde/pkg/validation"
	"log/slog"
	"net/http"
	"os"
	"strings"

	_ "garde/endpoint_documentation" // Swagger docs

	"garde/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
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
	// Load environment variables first
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file")
		os.Exit(1)
	}

	// Initialize logger
	logLevel := slog.LevelInfo // Default log level

	// Set log level
	envLogLevel := strings.ToUpper(os.Getenv("LOG_LEVEL"))
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

	// Load permissions. See readme for more information
	if err := models.LoadPermissions(); err != nil {
		slog.Warn("Failed to load permissions", "error", err)
		slog.Info("Running without permissions system")
	}

	// Load groups. See readme for more information
	if err := models.LoadGroups(); err != nil {
		slog.Warn("Failed to load groups", "error", err)
		slog.Info("Running without groups system")
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

	authService := service.NewAuthService(repo)
	securityAnalyzer := service.NewSecurityAnalyzer(repo)
	authHandler := handlers.NewAuthHandler(authService)

	// Initialize superuser
	err = authService.InitializeSuperUser(context.Background())
	if err != nil {
		slog.Error("Failed to initialize superuser", "error", err)
		os.Exit(1)
	}

	rateLimiter := middleware.NewRateLimiter(repo)

	router := gin.New()
	router.Use(middleware.Recovery()) // Recovery middleware (to not to expose error details during panic)
	router.Use(gin.Logger())

	router.Use(middleware.CORSMiddleware())

	// Security headers middleware with strict CSP
	router.Use(func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

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
	{
		protected.GET("/users/me", authHandler.GetCurrentUser)
		protected.POST("/logout", authHandler.Logout)
		protected.POST("/users/password/change", authHandler.ChangePassword)
		protected.POST("/users/mfa/setup", middleware.ConditionalAuthMiddleware(authService), authHandler.SetupMFA)
		protected.POST("/users/mfa/verify", middleware.ConditionalAuthMiddleware(authService), authHandler.VerifyAndEnableMFA)
		protected.POST("/users/mfa/disable", authHandler.DisableMFA)
		protected.POST("/users/request-update-from-admin", authHandler.RequestUpdate)
	}

	// Admin-only endpoints (require admin login, but no mTLS)
	adminProtected := router.Group("")
	adminProtected.Use(middleware.AdminMiddleware(authService))
	adminProtected.Use(middleware.AuthMiddleware(authService, securityAnalyzer))
	{
		adminProtected.GET("/users", authHandler.ListUsers)
		adminProtected.GET("/users/:user_id", authHandler.GetUser)
		adminProtected.PUT("/users/:user_id", authHandler.UpdateUser)
		adminProtected.POST("/sessions/revoke", authHandler.RevokeUserSession)
	}

	// Special case for /validate endpoint (API key + mTLS authentication only)
	validateEndpoint := router.Group("/validate")
	validateEndpoint.Use(func(c *gin.Context) {
		// First check for mTLS - this must happen before anything else
		if strings.ToLower(os.Getenv("USE_TLS")) == "true" {
			// Apply mTLS middleware first
			middleware.MTLSMiddleware()(c)
			if c.IsAborted() {
				return
			}
		}

		// Then check for API key
		apiKey := c.GetHeader(middleware.APIKeyHeader)
		if apiKey == "" {
			// Reject requests without API key
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.NewErrorResponse(errors.ErrUnauthorized))
			return
		}
		middleware.APIKeyMiddleware()(c)

		// After mTLS and API key are verified, validate the session
		if c.IsAborted() {
			return
		}
	})
	// Apply the auth middleware last after mTLS and API key checks
	validateEndpoint.Use(middleware.AuthMiddleware(authService, securityAnalyzer))
	validateEndpoint.GET("", authHandler.ValidateSession)

	// Swagger
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	var srv *http.Server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8443"
	}
	useTLS := strings.ToLower(os.Getenv("USE_TLS")) == "true"

	// TLS - mTLS
	if useTLS {

		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.RequireAndVerifyClientCert, // Require client certificates
		}

		cert, err := tls.LoadX509KeyPair(os.Getenv("TLS_CERT_PATH"), os.Getenv("TLS_KEY_PATH"))
		if err != nil {
			slog.Error("Failed to load server certificate", "error", err)
			os.Exit(1)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		if caPath := os.Getenv("TLS_CA_PATH"); caPath != "" {
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
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					slog.Info("Server loaded CA cert", "subject", cert.Subject, "issuer", cert.Issuer)
				}
			}

			tlsConfig.ClientCAs = caCertPool
			slog.Info("Loaded CA certificates for client verification - mTLS is enabled")
		} else {
			slog.Warn("No CA certificates provided for client verification")
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
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			slog.Error("Failed to start server", "error", err)
			os.Exit(1)
		}
	} else {
		srv = &http.Server{
			Addr:    ":" + port,
			Handler: router,
		}

		slog.Warn("Starting server without TLS", "port", port)
		if err := srv.ListenAndServe(); err != nil {
			slog.Error("Failed to start server", "error", err)
			os.Exit(1)
		}
	}
}
