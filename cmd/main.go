package main

import (
	"context"
	"fmt"
	"garde/internal/handlers"
	"garde/internal/httpmount"
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
	captchaHandler   *handlers.CaptchaHandler
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
		captchaHandler:   handlers.NewCaptchaHandler(repo),
		rateLimiter:      middleware.NewRateLimiter(repo),
	}

	router := newEngine(deps)
	mountDeps := &httpmount.Deps{
		Repo:             deps.repo,
		AuthService:      deps.authService,
		SecurityAnalyzer: deps.securityAnalyzer,
		AuthHandler:      deps.authHandler,
		APIKeyHandler:    deps.apiKeyHandler,
		PATHandler:       deps.patHandler,
		CaptchaHandler:   deps.captchaHandler,
		RateLimiter:      deps.rateLimiter,
	}
	httpmount.MountPublicListener(router, mountDeps)

	if config.GetBool("ENABLE_SWAGGER") {
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		slog.Info("Swagger UI enabled at /swagger/index.html")
	}

	if config.CapEnabled() {
		slog.Info("Cap captcha enabled for public auth routes",
			"api_url", config.CapAPIURL(),
			"public_url", config.CapPublicURL(),
			"site_key", config.CapSiteKey())
	} else {
		slog.Info("Cap captcha disabled")
	}
	config.LogRegistrationGates()

	servers := make([]*http.Server, 0, 2)

	publicSrv, err := newPublicServer(router)
	if err != nil {
		slog.Error("Failed to configure the public listener", "error", err)
		os.Exit(1)
	}
	servers = append(servers, publicSrv)

	if config.ServiceListenerEnabled() {
		serviceSrv, err := newServiceServer(deps, mountDeps)
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

// newEngine builds the middleware stack both listeners share. Probes are
// registered before the rate limiter so they are never throttled.
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
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		// Deny powerful features this app does not use. clipboard-write is
		// intentionally omitted so token/API-key copy still works.
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), midi=(), display-capture=(), accelerometer=(), gyroscope=(), magnetometer=()")
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

	router.Use(deps.rateLimiter.Limit())

	return router
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
