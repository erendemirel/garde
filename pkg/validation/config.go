package validation

import (
	"fmt"
	"os"
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
	if os.Getenv("REDIS_HOST") == "" {
		return fmt.Errorf("REDIS_HOST is required")
	}
	if os.Getenv("REDIS_PORT") == "" {
		return fmt.Errorf("REDIS_PORT is required")
	}
	if os.Getenv("REDIS_PASSWORD") == "" {
		return fmt.Errorf("REDIS_PASSWORD is required")
	}

	if strings.ToLower(os.Getenv("USE_TLS")) == "true" {
		if os.Getenv("TLS_CERT_PATH") == "" {
			return fmt.Errorf("TLS_CERT_PATH is required when USE_TLS is true")
		}
		if os.Getenv("TLS_KEY_PATH") == "" {
			return fmt.Errorf("TLS_KEY_PATH is required when USE_TLS is true")
		}
	}

	if os.Getenv("DOMAIN_NAME") == "" {
		return fmt.Errorf("DOMAIN_NAME is required")
	}

	// Superuser email
	if err := ValidateEmail(os.Getenv("SUPERUSER_EMAIL")); err != nil {
		return fmt.Errorf("SUPERUSER_EMAIL validation failed")
	}

	// Superuser password
	if err := ValidatePassword(os.Getenv("SUPERUSER_PASSWORD")); err != nil {
		return fmt.Errorf("SUPERUSER_PASSWORD validation failed")
	}

	// Validate API key if present
	if apiKey := os.Getenv("API_KEY"); apiKey != "" {
		if err := ValidateAPIKey(apiKey); err != nil {
			return fmt.Errorf("API_KEY validation failed")
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
