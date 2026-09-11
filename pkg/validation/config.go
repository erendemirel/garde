package validation

import (
	"encoding/json"
	"fmt"
	"garde/pkg/config"
	"strings"
	"unicode"
)

const (
	MaxHeaderLength     = 1024
	MaxQueryParamLength = 2048
	MaxPathParamLength  = 512
	MaxBodySize         = 1 << 20 // 1MB
)

type ValidatorConfig struct {
	MaxHeaderLength     int
	MaxQueryParamLength int
	MaxPathParamLength  int
	MaxBodySize         int64
}

func DefaultConfig() *ValidatorConfig {
	return &ValidatorConfig{
		MaxHeaderLength:     MaxHeaderLength,
		MaxQueryParamLength: MaxQueryParamLength,
		MaxPathParamLength:  MaxPathParamLength,
		MaxBodySize:         MaxBodySize,
	}
}

func ValidateConfig() error {
	// Redis configuration
	if config.Get("REDIS_HOST") == "" {
		return fmt.Errorf("REDIS_HOST is required")
	}
	if config.Get("REDIS_PORT") == "" {
		return fmt.Errorf("REDIS_PORT is required")
	}
	dockerProfile := config.Get("DOCKER_PROFILE")
	if config.Get("REDIS_PASSWORD") == "" {
		return fmt.Errorf("REDIS_PASSWORD is required")
	}

	if config.GetBool("USE_TLS") {
		if config.Get("TLS_CERT_PATH") == "" {
			return fmt.Errorf("TLS_CERT_PATH is required when USE_TLS is true")
		}
		if config.Get("TLS_KEY_PATH") == "" {
			return fmt.Errorf("TLS_KEY_PATH is required when USE_TLS is true")
		}
	}

	if err := validateListenerPolicy(); err != nil {
		return err
	}

	// DOMAIN_NAME is optional in dev mode (DOCKER_PROFILE=with-redis)
	// For local dev, cookies will work without domain set
	if dockerProfile != "with-redis" && config.Get("DOMAIN_NAME") == "" {
		return fmt.Errorf("DOMAIN_NAME is required")
	}

	// Superuser email
	if err := ValidateEmail(config.Get("SUPERUSER_EMAIL")); err != nil {
		return fmt.Errorf("SUPERUSER_EMAIL validation failed")
	}

	// Superuser password
	if err := ValidatePassword(config.Get("SUPERUSER_PASSWORD")); err != nil {
		return fmt.Errorf("SUPERUSER_PASSWORD validation failed")
	}

	// Validate API key if present
	if apiKey := config.Get("API_KEY"); apiKey != "" {
		if err := ValidateAPIKey(apiKey); err != nil {
			return fmt.Errorf("API_KEY validation failed")
		}
	}

	// Validate admin users JSON if provided
	if raw := config.Get("ADMIN_USERS_JSON"); raw != "" {
		adminMap, err := parseAdminUsers(raw)
		if err != nil {
			return err
		}
		for email, pwd := range adminMap {
			if err := ValidateEmail(email); err != nil {
				return fmt.Errorf("ADMIN_USERS_JSON email validation failed")
			}
			if err := ValidatePassword(pwd); err != nil {
				return fmt.Errorf("ADMIN_USERS_JSON password validation failed")
			}
		}
	}

	if err := validateAdminScopes(); err != nil {
		return err
	}

	return nil
}

// ADMIN_SCOPES_JSON is checked hard rather than warned about, because both of
// its likely mistakes fail the same silent way at runtime: an entry that
// names nobody, and a scope name with a typo, each leave the admin you meant
// to restrict holding their full bundle with nothing to tell you. Refusing to
// start is the only place that failure is visible.
func validateAdminScopes() error {
	raw := strings.TrimSpace(config.Get(config.AdminScopesKey))
	if raw == "" {
		return nil
	}

	scopeMap := map[string][]string{}
	if err := json.Unmarshal([]byte(raw), &scopeMap); err != nil {
		return fmt.Errorf("ADMIN_SCOPES_JSON is not valid JSON")
	}

	admins := config.GetAdminUsersMap()
	superuser := config.Get("SUPERUSER_EMAIL")

	for email, scopes := range scopeMap {
		if err := ValidateEmail(email); err != nil {
			return fmt.Errorf("ADMIN_SCOPES_JSON email validation failed")
		}
		if email == superuser {
			return fmt.Errorf("ADMIN_SCOPES_JSON must not list the superuser, who holds every scope by definition")
		}
		if _, isAdmin := admins[email]; !isAdmin {
			return fmt.Errorf("ADMIN_SCOPES_JSON names an address absent from ADMIN_USERS_JSON, so it would restrict nobody")
		}
		for _, scope := range scopes {
			if !config.IsKnownAdminScope(scope) {
				return fmt.Errorf("ADMIN_SCOPES_JSON contains an unknown scope; known scopes are %s", strings.Join(config.AllAdminScopes(), ", "))
			}
		}
	}

	return nil
}

// Checks the client-certificate policies against the material they need, and
// what /validate accepts against what the deployment said it wants. These fail
// the process at startup rather than at the first request: a listener that
// silently downgrades to "no certificate required", or to "one shared secret
// is enough", is the exact failure this split exists to prevent.
func validateListenerPolicy() error {
	if config.BrowserMTLS() != config.ClientCertOff {
		if !config.GetBool("USE_TLS") {
			return fmt.Errorf("BROWSER_MTLS requires USE_TLS — client certificates cannot be verified by a proxy that terminates TLS elsewhere")
		}
		if config.Get("TLS_CA_PATH") == "" {
			return fmt.Errorf("TLS_CA_PATH is required when BROWSER_MTLS is %s", config.BrowserMTLS())
		}
	}

	if err := validatePublicValidateSharedKey(); err != nil {
		return err
	}

	if !config.ServiceListenerEnabled() {
		return nil
	}

	if config.ServiceTLSCertPath() == "" || config.ServiceTLSKeyPath() == "" {
		return fmt.Errorf("SERVICE_TLS_CERT_PATH and SERVICE_TLS_KEY_PATH are required when SERVICE_LISTENER is true")
	}
	if config.ServiceMTLS() == config.ClientCertRequired && config.ServiceTLSCAPath() == "" {
		return fmt.Errorf("SERVICE_TLS_CA_PATH is required when SERVICE_MTLS is required")
	}
	if config.ServicePort() == config.GetWithDefault("PORT", "8443") {
		return fmt.Errorf("SERVICE_PORT must differ from PORT (both are %s)", config.ServicePort())
	}

	return nil
}

// The shared API_KEY authenticating a public /validate has no safe default, so
// it gets no default: the deployment states which posture it wants or the
// process does not start. Requiring the statement only where it changes
// something keeps it from becoming boilerplate — a deployment whose /validate
// is private, or not served at all, is never asked.
func validatePublicValidateSharedKey() error {
	allow, configured, valid := config.PublicValidateSharedKey()

	if configured && !valid {
		return fmt.Errorf("%s must be true or false", config.PublicValidateSharedKeyKey)
	}

	// The split already refuses the shared key on the public copy of /validate,
	// so there is nothing here to decide. Saying otherwise is refused instead
	// of ignored: a security setting that reads as honoured and is not is worse
	// than one that fails.
	if config.ServiceListenerEnabled() {
		if configured && allow {
			return fmt.Errorf("%s=true cannot be honoured while SERVICE_LISTENER is true: the public /validate then exists for external callers and accepts per-caller keys only. Remove the setting, or turn the service listener off", config.PublicValidateSharedKeyKey)
		}
		return nil
	}

	if !config.PublicValidateEnabled() || configured {
		return nil
	}

	return fmt.Errorf("%s must be set: /validate is served on the public listener, where the shared API_KEY would authenticate it — one long-lived secret, held by every caller, in front of an endpoint that can validate any user's session. "+
		"Set it to false to refuse the shared key there and require per-caller keys from POST /admin/api-keys, set SERVICE_LISTENER=true to move /validate to a private listener instead, or set it to true to keep accepting the shared key",
		config.PublicValidateSharedKeyKey)
}

func ValidateAPIKey(key string) error {
	if len(key) < 20 {
		return fmt.Errorf("API_KEY must be at least 20 characters long")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range key {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return fmt.Errorf("API_KEY must contain at least one uppercase letter, one lowercase letter, one number and one special character")
	}

	return nil
}

func parseAdminUsers(raw string) (map[string]string, error) {
	adminMap := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &adminMap); err != nil {
		if fallback, ok := parseAdminUsersFallback(raw); ok {
			return fallback, nil
		}
		return nil, fmt.Errorf("ADMIN_USERS_JSON is not valid JSON: %w", err)
	}
	return adminMap, nil
}

// parseAdminUsersFallback parses "email:pwd,email2:pwd2" or "email=pwd" style strings.
func parseAdminUsersFallback(raw string) (map[string]string, bool) {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, "{}")
	items := strings.Split(raw, ",")
	result := make(map[string]string)
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		trimmed = strings.Trim(trimmed, "\"")
		if trimmed == "" {
			continue
		}
		sep := ":"
		if strings.Contains(trimmed, "=") && !strings.Contains(trimmed, ":") {
			sep = "="
		}
		parts := strings.SplitN(trimmed, sep, 2)
		if len(parts) != 2 {
			return nil, false
		}
		email := strings.TrimSpace(strings.Trim(parts[0], "\""))
		pwd := strings.TrimSpace(strings.Trim(parts[1], "\""))
		if email == "" || pwd == "" {
			return nil, false
		}
		result[email] = pwd
	}
	if len(result) == 0 {
		return nil, false
	}
	return result, true
}
