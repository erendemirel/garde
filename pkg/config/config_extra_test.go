package config

import (
	"testing"
)

func TestMustGetAndSecretsDir(t *testing.T) {
	withSecrets(t, map[string]string{"present": "yes"})
	if got := MustGet("present"); got != "yes" {
		t.Fatalf("got %q", got)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustGet on missing key did not panic")
		}
	}()
	MustGet("absent")
}

func TestGetSecretsDirSet(t *testing.T) {
	withSecrets(t, map[string]string{})
	if GetSecretsDir() == "" {
		t.Fatal("empty secrets dir after Init")
	}
}

func TestGetAdminScopesMapShapes(t *testing.T) {
	withSecrets(t, map[string]string{})
	if m := GetAdminScopesMap(); m != nil {
		t.Fatalf("unset = %v, want nil", m)
	}
	withSecrets(t, map[string]string{
		"admin_scopes_json": `{"helpdesk@example.com":["garde:users:read"]}`,
	})
	m := GetAdminScopesMap()
	if len(m) != 1 || len(m["helpdesk@example.com"]) != 1 {
		t.Fatalf("map = %v", m)
	}
}

func TestServiceTLSPathGetters(t *testing.T) {
	withSecrets(t, map[string]string{
		"service_tls_cert_path": " c.pem ",
		"service_tls_key_path":  "k.pem",
		"service_tls_ca_path":   "",
		"service_port":          "9443",
		"service_bind":          " 127.0.0.1 ",
	})
	if got := ServiceTLSCertPath(); got != "c.pem" {
		t.Fatalf("cert = %q", got)
	}
	if got := ServiceTLSKeyPath(); got != "k.pem" {
		t.Fatalf("key = %q", got)
	}
	if got := ServiceTLSCAPath(); got != "" {
		t.Fatalf("ca = %q, want empty", got)
	}
	if got := ServicePort(); got != "9443" {
		t.Fatalf("port = %q", got)
	}
	if got := ServiceBind(); got != "127.0.0.1" {
		t.Fatalf("bind = %q", got)
	}
	withSecrets(t, map[string]string{})
	if got := ServicePort(); got != "8444" {
		t.Fatalf("default port = %q, want 8444", got)
	}
}
