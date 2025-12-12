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
	allowEmptyPassword := dockerProfile == "with-redis"
	if !allowEmptyPassword && config.Get("REDIS_PASSWORD") == "" {
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

	if config.Get("DOMAIN_NAME") == "" {
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

	return nil
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
