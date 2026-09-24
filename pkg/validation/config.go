package validation

import (
	"encoding/json"
	"fmt"
	"garde/pkg/config"
	"garde/pkg/crypto"
	"strings"
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
	if err := validatePostgresConfig(); err != nil {
		return err
	}

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

	if err := validateMFAEncryptionKey(); err != nil {
		return err
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

	if err := config.ValidateEmailDomainLists(); err != nil {
		return err
	}
	if err := validateBootstrapEmailsAgainstDomainPolicy(); err != nil {
		return err
	}

	return nil
}

// Bootstrap accounts must satisfy the same registration domain policy when lists
// are set — otherwise operators can lock themselves into an unreachable login
// surface or an inconsistent allowlist.
func validateBootstrapEmailsAgainstDomainPolicy() error {
	if !config.EmailDomainPolicyConfigured() {
		return nil
	}
	if err := ValidateEmailDomainPolicy(config.Get("SUPERUSER_EMAIL")); err != nil {
		return fmt.Errorf("SUPERUSER_EMAIL is excluded by EMAIL_ALLOWED_DOMAINS / EMAIL_BLOCKED_DOMAINS")
	}
	for email := range config.GetAdminUsersMap() {
		if err := ValidateEmailDomainPolicy(email); err != nil {
			return fmt.Errorf("ADMIN_USERS_JSON email %q is excluded by EMAIL_ALLOWED_DOMAINS / EMAIL_BLOCKED_DOMAINS", email)
		}
	}
	return nil
}

func validateMFAEncryptionKey() error {
	if _, err := crypto.ParseMFAEncryptionKey(config.Get("MFA_ENCRYPTION_KEY")); err != nil {
		return err
	}
	return nil
}

// PostgreSQL is the durable authority. Prefer DATABASE_URL; otherwise require
// the discrete POSTGRES_* secrets so a misconfigured node fails at startup
// rather than on the first account write.
func validatePostgresConfig() error {
	if strings.TrimSpace(config.Get("DATABASE_URL")) != "" {
		return nil
	}
	if strings.TrimSpace(config.Get("POSTGRES_HOST")) == "" {
		return fmt.Errorf("DATABASE_URL or POSTGRES_HOST is required")
	}
	if strings.TrimSpace(config.Get("POSTGRES_DB")) == "" {
		return fmt.Errorf("POSTGRES_DB is required when DATABASE_URL is not set")
	}
	if strings.TrimSpace(config.Get("POSTGRES_USER")) == "" {
		return fmt.Errorf("POSTGRES_USER is required when DATABASE_URL is not set")
	}
	return nil
}

// ADMIN_SCOPES_JSON is checked hard rather than warned about. Mistakes that
// used to leave admins unrestricted (unknown emails, typos, missing admins)
// refuse to start instead.
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
	superuser := strings.ToLower(strings.TrimSpace(config.Get("SUPERUSER_EMAIL")))

	normalized := make(map[string][]string, len(scopeMap))
	for email, scopes := range scopeMap {
		if err := ValidateEmail(email); err != nil {
			return fmt.Errorf("ADMIN_SCOPES_JSON email validation failed")
		}
		key := strings.ToLower(strings.TrimSpace(email))
		if key == superuser {
			return fmt.Errorf("ADMIN_SCOPES_JSON must not list the superuser, who holds every scope by definition")
		}
		if _, isAdmin := admins[key]; !isAdmin {
			return fmt.Errorf("ADMIN_SCOPES_JSON names an address absent from ADMIN_USERS_JSON, so it would restrict nobody")
		}
		for _, scope := range scopes {
			if !config.IsKnownAdminScope(scope) {
				return fmt.Errorf("ADMIN_SCOPES_JSON contains an unknown scope; known scopes are %s", strings.Join(config.AllAdminScopes(), ", "))
			}
		}
		normalized[key] = scopes
	}

	for email := range admins {
		if _, ok := normalized[email]; !ok {
			return fmt.Errorf("ADMIN_SCOPES_JSON must list every ADMIN_USERS_JSON address when set (missing %s)", email)
		}
	}

	return nil
}

// Checks the client-certificate policies against the material they need.
// These fail the process at startup rather than at the first request: a
// listener that silently downgrades to "no certificate required" is the
// failure this split exists to prevent.
func validateListenerPolicy() error {
	if config.BrowserMTLS() != config.ClientCertOff {
		if !config.GetBool("USE_TLS") {
			return fmt.Errorf("BROWSER_MTLS requires USE_TLS — client certificates cannot be verified by a proxy that terminates TLS elsewhere")
		}
		if config.Get("TLS_CA_PATH") == "" {
			return fmt.Errorf("TLS_CA_PATH is required when BROWSER_MTLS is %s", config.BrowserMTLS())
		}
	}

	// Kill switch with no service listener leaves auth mounted nowhere while
	// /ready stays green — fail closed rather than serving a hollow process.
	if !config.PublicSelfServiceEnabled() && !config.ServiceListenerEnabled() {
		return fmt.Errorf("PUBLIC_SELF_SERVICE=false requires SERVICE_LISTENER=true — otherwise no auth listener is available")
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

func parseAdminUsers(raw string) (map[string]string, error) {
	adminMap := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &adminMap); err != nil {
		return nil, fmt.Errorf("ADMIN_USERS_JSON is not valid JSON: %w", err)
	}
	return adminMap, nil
}
