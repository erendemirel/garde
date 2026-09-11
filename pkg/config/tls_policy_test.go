package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Secrets arrive as one file per key, so a test fixture is a directory.
func withSecrets(t *testing.T, values map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, value := range values {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatalf("writing secret %s: %v", name, err)
		}
	}
	if err := Init(dir); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
}

func TestBrowserMTLSDefaultsToOff(t *testing.T) {
	withSecrets(t, map[string]string{})

	if got := BrowserMTLS(); got != ClientCertOff {
		t.Fatalf("BrowserMTLS() = %v, want off — a public listener must not demand certificates", got)
	}
}

func TestClientCertPolicyParsing(t *testing.T) {
	cases := []struct {
		raw     string
		browser ClientCertPolicy
		service ClientCertPolicy
	}{
		{"", ClientCertOff, ClientCertRequired},
		{"off", ClientCertOff, ClientCertOff},
		{"required", ClientCertRequired, ClientCertRequired},
		{"REQUIRED", ClientCertRequired, ClientCertRequired},
		{"nonsense", ClientCertOff, ClientCertRequired},
		// "optional" has no meaning on a listener that exists for machines:
		// it degrades to required rather than silently weakening.
		{"optional", ClientCertOptional, ClientCertRequired},
	}

	for _, tc := range cases {
		withSecrets(t, map[string]string{
			"browser_mtls": tc.raw,
			"service_mtls": tc.raw,
		})

		if got := BrowserMTLS(); got != tc.browser {
			t.Errorf("BrowserMTLS(%q) = %v, want %v", tc.raw, got, tc.browser)
		}
		if got := ServiceMTLS(); got != tc.service {
			t.Errorf("ServiceMTLS(%q) = %v, want %v", tc.raw, got, tc.service)
		}
	}
}

func TestPublicValidateFollowsTheServiceListener(t *testing.T) {
	withSecrets(t, map[string]string{})
	if !PublicValidateEnabled() {
		t.Fatal("without a service listener /validate must stay on the public listener")
	}

	withSecrets(t, map[string]string{"service_listener": "true"})
	if PublicValidateEnabled() {
		t.Fatal("enabling the service listener must move /validate off the public listener")
	}

	// An operator who deliberately wants both says so.
	withSecrets(t, map[string]string{"service_listener": "true", "public_validate": "true"})
	if !PublicValidateEnabled() {
		t.Fatal("PUBLIC_VALIDATE=true must override the default")
	}
}

func TestPublicValidateMTLSRequiresBuiltInTLSAndCA(t *testing.T) {
	// Behind a TLS-terminating proxy there is no client certificate to check,
	// so the endpoint falls back to API key only — which is why it should not
	// be published there.
	withSecrets(t, map[string]string{"use_tls": "false", "tls_ca_path": "/app/certs/ca.pem"})
	if got := PublicValidateMTLS(); got != ClientCertOff {
		t.Fatalf("PublicValidateMTLS() = %v, want off when USE_TLS is false", got)
	}

	withSecrets(t, map[string]string{"use_tls": "true", "tls_ca_path": "/app/certs/ca.pem"})
	if got := PublicValidateMTLS(); got != ClientCertRequired {
		t.Fatalf("PublicValidateMTLS() = %v, want required with built-in TLS and a client CA", got)
	}
}

func TestPublicValidateMTLSOffForExternalTenants(t *testing.T) {
	// With the service listener carrying the operator's own services, a public
	// /validate exists for external callers. They hold a per-tenant API key and
	// no certificate, so the TLS-plus-CA inference must not apply to them.
	withSecrets(t, map[string]string{
		"use_tls":          "true",
		"tls_ca_path":      "/app/certs/ca.pem",
		"service_listener": "true",
		"public_validate":  "true",
	})
	if got := PublicValidateMTLS(); got != ClientCertOff {
		t.Fatalf("PublicValidateMTLS() = %v, want off — tenants have no client certificate", got)
	}

	// BROWSER_MTLS=required still wins: that listener exists for certificate
	// holders and nothing else.
	withSecrets(t, map[string]string{
		"use_tls":          "true",
		"tls_ca_path":      "/app/certs/ca.pem",
		"browser_mtls":     "required",
		"service_listener": "true",
		"public_validate":  "true",
	})
	if got := PublicValidateMTLS(); got != ClientCertRequired {
		t.Fatalf("PublicValidateMTLS() = %v, want required when BROWSER_MTLS demands it", got)
	}
}

func TestPublicValidateLegacyKey(t *testing.T) {
	// Single listener, acknowledged: the shared key is the only credential
	// /validate has ever had there, so it keeps working when asked for.
	withSecrets(t, map[string]string{"public_validate_shared_key": "true"})
	if !PublicValidateLegacyKey() {
		t.Fatal("an acknowledged single-listener deployment must still accept the shared API key")
	}

	// The posture single-listener deployments could not reach before: refuse
	// the shared key without standing up the mesh listener and its PKI.
	withSecrets(t, map[string]string{"public_validate_shared_key": "false"})
	if PublicValidateLegacyKey() {
		t.Fatal("PUBLIC_VALIDATE_SHARED_KEY=false must refuse the shared key on the public listener")
	}

	// Once /validate is published alongside a service listener, it is there for
	// external tenants, and one secret shared by all of them is the exposure
	// the split removed. The setting cannot buy it back.
	withSecrets(t, map[string]string{
		"service_listener":           "true",
		"public_validate":            "true",
		"public_validate_shared_key": "true",
	})
	if PublicValidateLegacyKey() {
		t.Fatal("the shared API key must not authenticate the tenant-facing /validate")
	}
}

// Startup validation refuses both of these, so they are only reachable by
// skipping it. Landing on "refuse the shared key" costs callers 401s; landing
// on "accept it" hands a session validator to anyone holding one secret.
func TestPublicValidateLegacyKeyFailsClosed(t *testing.T) {
	withSecrets(t, map[string]string{})
	if PublicValidateLegacyKey() {
		t.Error("an unset acknowledgement must not accept the shared key")
	}

	withSecrets(t, map[string]string{"public_validate_shared_key": "sure"})
	if PublicValidateLegacyKey() {
		t.Error("an unparseable acknowledgement must not accept the shared key")
	}
}

func TestPublicValidateSharedKeyParsing(t *testing.T) {
	cases := []struct {
		raw                        string
		allow, configured, isValid bool
	}{
		{"", false, false, true},
		{"true", true, true, true},
		{"TRUE", true, true, true},
		{" yes ", true, true, true},
		{"1", true, true, true},
		{"on", true, true, true},
		{"false", false, true, true},
		{"off", false, true, true},
		{"0", false, true, true},
		// GetBool would read this as false. A typo must not pick a posture.
		{"flase", false, true, false},
	}

	for _, tc := range cases {
		withSecrets(t, map[string]string{"public_validate_shared_key": tc.raw})

		allow, configured, valid := PublicValidateSharedKey()
		if allow != tc.allow || configured != tc.configured || valid != tc.isValid {
			t.Errorf("PublicValidateSharedKey(%q) = (%t, %t, %t), want (%t, %t, %t)",
				tc.raw, allow, configured, valid, tc.allow, tc.configured, tc.isValid)
		}
	}
}

func TestServiceListenerDefaults(t *testing.T) {
	withSecrets(t, map[string]string{})

	if ServiceListenerEnabled() {
		t.Error("the service listener must be opt-in")
	}
	if got := ServicePort(); got != defaultServicePort {
		t.Errorf("ServicePort() = %q, want %q", got, defaultServicePort)
	}
	if got := ServiceBind(); got != "" {
		t.Errorf("ServiceBind() = %q, want empty (the host publishes the port, not the process)", got)
	}
}
