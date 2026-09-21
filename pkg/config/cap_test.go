package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCapEnabledRequiresAllFields(t *testing.T) {
	dir := t.TempDir()
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("cap_enabled", "true")
	write("cap_site_key", "sk")
	write("cap_secret_key", "sec")
	write("cap_api_url", "http://cap:3000/")
	write("cap_public_url", "http://localhost:3000")

	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	if !CapEnabled() {
		t.Fatal("expected CapEnabled true")
	}
	if CapAPIURL() != "http://cap:3000" {
		t.Fatalf("CapAPIURL = %q", CapAPIURL())
	}
	if CapWidgetEndpoint() != "http://localhost:3000/sk/" {
		t.Fatalf("CapWidgetEndpoint = %q", CapWidgetEndpoint())
	}

	write("cap_secret_key", "")
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	if CapEnabled() {
		t.Fatal("expected CapEnabled false when secret missing")
	}
}
