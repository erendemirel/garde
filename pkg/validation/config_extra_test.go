package validation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"garde/pkg/config"
)

func validSecrets() map[string]string {
	return map[string]string{
		"postgres_host":      "localhost",
		"postgres_port":      "5432",
		"postgres_user":      "garde",
		"postgres_password":  "garde",
		"postgres_db":        "garde",
		"redis_host":         "localhost",
		"redis_port":         "6379",
		"redis_password":     "redis",
		"domain_name":        "example.com",
		"superuser_email":    "root@example.com",
		"superuser_password": "DevAdminTest123!",
		"mfa_encryption_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
	}
}

func initValidationConfig(t *testing.T, secrets map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, value := range secrets {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultConfigMatchesConstants(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxHeaderLength != MaxHeaderLength || cfg.MaxQueryParamLength != MaxQueryParamLength ||
		cfg.MaxPathParamLength != MaxPathParamLength || cfg.MaxBodySize != MaxBodySize {
		t.Fatalf("defaults drifted: %+v", cfg)
	}
}

func TestValidateConfigTable(t *testing.T) {
	mk := func(overrides map[string]string, drop ...string) map[string]string {
		secrets := validSecrets()
		for _, k := range drop {
			delete(secrets, k)
		}
		for k, v := range overrides {
			secrets[k] = v
		}
		return secrets
	}

	cases := []struct {
		name    string
		secrets map[string]string
		wantErr bool
	}{
		{"minimal valid", mk(nil), false},
		{"missing postgres host", mk(nil, "postgres_host"), true},
		{"missing postgres db", mk(nil, "postgres_db"), true},
		{"database_url alone is enough", mk(map[string]string{"database_url": "postgres://garde:garde@localhost:5432/garde?sslmode=disable"}, "postgres_host", "postgres_db", "postgres_user", "postgres_password"), false},
		{"missing redis host", mk(nil, "redis_host"), true},
		{"missing redis password", mk(nil, "redis_password"), true},
		{"missing domain", mk(nil, "domain_name"), true},
		{"bad superuser email", mk(map[string]string{"superuser_email": "nope"}), true},
		{"weak superuser password", mk(map[string]string{"superuser_password": "password"}), true},
		{"missing mfa encryption key", mk(nil, "mfa_encryption_key"), true},
		{"passphrase mfa encryption key", mk(map[string]string{"mfa_encryption_key": "not-32-byte-base64"}), true},
		{"bad admin json", mk(map[string]string{"admin_users_json": ";;"}), true},
		{"weak admin password", mk(map[string]string{"admin_users_json": `{"a@example.com":"weak"}`}), true},
		{"valid admin json", mk(map[string]string{"admin_users_json": `{"a@example.com":"DevAdminTest123!"}`}), false},
		{"kill switch without service listener", mk(map[string]string{"public_self_service": "false"}), true},
		{"kill switch with service listener", mk(map[string]string{
			"public_self_service":   "false",
			"service_listener":      "true",
			"service_port":          "9443",
			"service_tls_cert_path": "/certs/service.crt",
			"service_tls_key_path":  "/certs/service.key",
			"service_mtls":          "off",
		}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			initValidationConfig(t, tc.secrets)
			err := ValidateConfig()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseAdminUsersShapes(t *testing.T) {
	m, err := parseAdminUsers(`{"a@example.com":"Pw1!"}`)
	if err != nil || len(m) != 1 {
		t.Fatalf("json = %v, %v", m, err)
	}
	if _, err := parseAdminUsers("a@example.com:Pw1!"); err == nil {
		t.Fatal("non-JSON accepted")
	}
	if _, err := parseAdminUsers(";;;"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestPasswordErrorHasErrors(t *testing.T) {
	if (PasswordError{}).HasErrors() {
		t.Fatal("zero value reports errors")
	}
	if !(PasswordError{NoUpper: true}).HasErrors() {
		t.Fatal("flagged error not reported")
	}
}

func TestValidatePATNameDelegates(t *testing.T) {
	if err := ValidatePATName("ci-token_1.0"); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if err := ValidatePATName("bad name!"); err == nil {
		t.Fatal("invalid accepted")
	}
	if !strings.Contains(ValidatePATName("").Error(), "token name") {
		t.Fatal("error should name the PAT field")
	}
}
