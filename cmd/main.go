package main

import (
	"garde/internal/handlers"
	"garde/internal/middleware"
	"garde/internal/repository"
	"garde/internal/service"
	"garde/pkg/errors"
	"garde/pkg/validation"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
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

	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Load permissions. See readme for more information
	if err := models.LoadPermissions(); err != nil {
		log.Printf("Warning: Failed to load permissions: %v", err)
		log.Println("Running without permissions system")
	}

	// Load groups. See readme for more information
	if err := models.LoadGroups(); err != nil {
		log.Printf("Warning: Failed to load groups: %v", err)
		log.Println("Running without groups system")
	}

	if err := validation.ValidateConfig(); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	var repo *repository.RedisRepository
	var err error

	log.Println("Connecting to Redis...")
	repo, err = repository.NewRedisRepository()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	log.Println("Connected to Redis successfully")

	authService := service.NewAuthService(repo)
	securityAnalyzer := service.NewSecurityAnalyzer(repo)
	authHandler := handlers.NewAuthHandler(authService)

	// Initialize superuser
	err = authService.InitializeSuperUser(context.Background())
	if err != nil {
		log.Fatalf("Failed to initialize superuser: %v", err)
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
			log.Fatalf("Failed to load server certificate: %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		if caPath := os.Getenv("TLS_CA_PATH"); caPath != "" {
			caCertPool := x509.NewCertPool()
			caCert, err := os.ReadFile(caPath)
			if err != nil {
				log.Fatalf("Failed to read CA certificate: %v", err)
			}
			if !caCertPool.AppendCertsFromPEM(caCert) {
				log.Fatal("Failed to append CA certificate")
			}

			block, _ := pem.Decode(caCert)
			if block != nil {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					log.Printf("Server loaded CA cert with Subject: %v, Issuer: %v", cert.Subject, cert.Issuer)
				}
			}

			tlsConfig.ClientCAs = caCertPool
			log.Printf("Loaded CA certificates for client verification - mTLS is enabled")
		} else {
			log.Printf("Warning: No CA certificates provided for client verification")
		}

		if len(cert.Certificate) > 0 {
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				log.Printf("Server using certificate - Subject: %v, Issuer: %v", x509Cert.Subject, x509Cert.Issuer)
			}
		}

		srv = &http.Server{
			Addr:      ":" + port,
			Handler:   router,
			TLSConfig: tlsConfig,
		}

		log.Printf("Starting server on port %s with TLS", port)
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	} else {
		srv = &http.Server{
			Addr:    ":" + port,
			Handler: router,
		}

		log.Printf("Warning: Starting server on port %s without TLS", port)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}
}
