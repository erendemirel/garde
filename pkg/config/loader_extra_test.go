package config

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func initDir(t *testing.T, secrets map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, value := range secrets {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
}

func TestGetCookieSameSiteTable(t *testing.T) {
	cases := []struct {
		value string
		want  http.SameSite
	}{
		{"", http.SameSiteLaxMode},
		{"lax", http.SameSiteLaxMode},
		{"strict", http.SameSiteStrictMode},
		{"none", http.SameSiteNoneMode},
		{"STRICT", http.SameSiteStrictMode},
		{"bogus", http.SameSiteLaxMode},
	}
	for _, tc := range cases {
		initDir(t, map[string]string{"cookie_same_site": tc.value})
		if got := GetCookieSameSite(); got != tc.want {
			t.Fatalf("value %q: got %v want %v", tc.value, got, tc.want)
		}
	}
}

func TestGetCookieSecureTable(t *testing.T) {
	cases := []struct {
		name    string
		secrets map[string]string
		want    bool
	}{
		{"explicit true", map[string]string{"cookie_secure": "true"}, true},
		{"explicit false beats tls", map[string]string{"cookie_secure": "false", "use_tls": "true"}, false},
		{"tls implies secure", map[string]string{"use_tls": "true"}, true},
		{"samesite none forces secure", map[string]string{"cookie_same_site": "none"}, true},
		{"plain http default", map[string]string{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			initDir(t, tc.secrets)
			if got := GetCookieSecure(); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestGetAdminUsersMapShapes(t *testing.T) {
	initDir(t, map[string]string{"admin_users_json": `{"a@example.com":"Pw1!"}`})
	if m := GetAdminUsersMap(); len(m) != 1 || m["a@example.com"] != "Pw1!" {
		t.Fatalf("json shape = %v", m)
	}

	initDir(t, map[string]string{"admin_users_json": "a@example.com:Pw1!,b@example.com=Pw2!"})
	if m := GetAdminUsersMap(); m != nil {
		t.Fatalf("non-JSON = %v, want nil", m)
	}

	initDir(t, map[string]string{})
	if m := GetAdminUsersMap(); m != nil {
		t.Fatalf("unset = %v, want nil", m)
	}

	initDir(t, map[string]string{"admin_users_json": "not a map at all;;;"})
	if m := GetAdminUsersMap(); m != nil {
		t.Fatalf("garbage = %v, want nil", m)
	}
}

func TestGetWithDefaultAndBool(t *testing.T) {
	initDir(t, map[string]string{"present": "yes"})
	if got := GetWithDefault("present", "d"); got != "yes" {
		t.Fatalf("got %q", got)
	}
	if got := GetWithDefault("absent", "d"); got != "d" {
		t.Fatalf("got %q", got)
	}
	if !GetBoolWithDefault("present", false) {
		t.Fatal("yes should be true")
	}
	if !GetBoolWithDefault("absent", true) {
		t.Fatal("default not returned")
	}
	if Get("absent") != "" {
		t.Fatal("absent should be empty")
	}
}
