package middleware

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"garde/internal/models"
	"garde/internal/repository"
	"garde/pkg/config"
	pkgerrors "garde/pkg/errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	capTokenHeader     = "X-Cap-Token"
	capVerifyTimeout   = 5 * time.Second
	capVerifyUserAgent = "garde-cap-verify/1.0"
)

var capHTTPClient = &http.Client{Timeout: capVerifyTimeout}

type capVerifyRequest struct {
	Secret   string `json:"secret"`
	Response string `json:"response"`
}

type capVerifyResponse struct {
	Success bool `json:"success"`
}

// CapMiddleware rejects public auth requests that lack a valid Cap token when
// Cap is enabled. Login is progressive: Cap is required only after
// CapLoginFailureThreshold failed attempts for the email or IP. Register and
// password-reset always require Cap when enabled. Issued service API keys with
// the auth scope skip Cap. No-op when Cap is disabled.
func CapMiddleware(repo *repository.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !config.CapEnabled() {
			c.Next()
			return
		}

		if serviceAPIKeyHasScope(c, repo, models.ScopeAuth) {
			c.Next()
			return
		}

		if !capRequiredForRequest(c, repo) {
			c.Next()
			return
		}

		token := extractCapToken(c)
		if token == "" {
			c.AbortWithStatusJSON(
				http.StatusForbidden,
				models.NewErrorResponse(pkgerrors.ErrCaptchaRequired).WithCaptchaRequired(true),
			)
			return
		}

		if err := VerifyCapToken(c.Request.Context(), token); err != nil {
			slog.Warn("Cap verification failed", "error", err, "path", c.Request.URL.Path)
			c.AbortWithStatusJSON(
				http.StatusForbidden,
				models.NewErrorResponse(pkgerrors.ErrCaptchaFailed).WithCaptchaRequired(true),
			)
			return
		}

		c.Next()
	}
}

// LoginCaptchaRequired reports whether the next /login from this email/IP must
// include a Cap token. Used by handlers and /captcha/config.
func LoginCaptchaRequired(ctx context.Context, repo *repository.Store, email, ip string) bool {
	if !config.CapEnabled() || repo == nil {
		return false
	}
	n, err := repo.GetFailedLoginCount(ctx, strings.TrimSpace(strings.ToLower(email)), ip)
	if err != nil {
		slog.Warn("Failed to read failed-login count for Cap gate", "error", err)
		return true
	}
	return n >= config.CapLoginFailureThreshold
}

func capRequiredForRequest(c *gin.Context, repo *repository.Store) bool {
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}

	switch path {
	case "/login":
		email := loginEmailFromContext(c)
		return LoginCaptchaRequired(c.Request.Context(), repo, email, c.ClientIP())
	default:
		// Register + password OTP/reset stay always-on when Cap is enabled.
		return true
	}
}

func loginEmailFromContext(c *gin.Context) string {
	v, ok := c.Get(ContextKeyValidatedRequest)
	if !ok {
		return ""
	}
	req, ok := v.(models.LoginRequest)
	if !ok {
		return ""
	}
	return req.Email
}

func extractCapToken(c *gin.Context) string {
	if t := strings.TrimSpace(c.GetHeader(capTokenHeader)); t != "" {
		return t
	}

	v, ok := c.Get(ContextKeyValidatedRequest)
	if !ok {
		return ""
	}

	switch req := v.(type) {
	case models.LoginRequest:
		return strings.TrimSpace(req.CapToken)
	case models.CreateUserRequest:
		return strings.TrimSpace(req.CapToken)
	case models.RequestOTPRequest:
		return strings.TrimSpace(req.CapToken)
	case models.PasswordResetRequest:
		return strings.TrimSpace(req.CapToken)
	default:
		return ""
	}
}

// VerifyCapToken calls Cap Standalone's siteverify endpoint.
func VerifyCapToken(ctx context.Context, token string) error {
	if bypass := config.CapBypassToken(); bypass != "" &&
		subtle.ConstantTimeCompare([]byte(token), []byte(bypass)) == 1 {
		return nil
	}

	apiURL := config.CapAPIURL()
	siteKey := config.CapSiteKey()
	secret := config.CapSecretKey()
	if apiURL == "" || siteKey == "" || secret == "" {
		return fmt.Errorf("cap is not fully configured")
	}

	body, err := json.Marshal(capVerifyRequest{Secret: secret, Response: token})
	if err != nil {
		return fmt.Errorf("encode siteverify body: %w", err)
	}

	url := apiURL + "/" + siteKey + "/siteverify"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build siteverify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", capVerifyUserAgent)

	resp, err := capHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("siteverify request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read siteverify response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("siteverify status %d", resp.StatusCode)
	}

	var parsed capVerifyResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return fmt.Errorf("decode siteverify response: %w", err)
	}
	if !parsed.Success {
		return fmt.Errorf("siteverify success=false")
	}
	return nil
}
