package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ADMIN_USERS_JSON / scope maps are operator-supplied secrets parsed with encoding/json.
// Lock common shapes across the Go 1.27 json-v2-backed implementation.

func TestAdminUsersJSONRoundTripShapes(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{
			name: "simple",
			raw:  `{"admin@example.com":"DevAdminTest123!"}`,
			want: map[string]string{"admin@example.com": "DevAdminTest123!"},
		},
		{
			name: "unicode email local-part keys preserved",
			raw:  `{"admin+test@exämple.com":"Pw1!aaaa"}`,
			want: map[string]string{"admin+test@exämple.com": "Pw1!aaaa"},
		},
		{
			name: "empty object",
			raw:  `{}`,
			want: map[string]string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got map[string]string
			if err := json.Unmarshal([]byte(tc.raw), &got); err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len=%d want %d (%v)", len(got), len(tc.want), got)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("key %q: got %q want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestAdminUsersJSONInvalidRejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ADMIN_USERS_JSON"), []byte(`{"admin@x.com":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	got := GetAdminUsersMap()
	if len(got) != 0 {
		t.Fatalf("truncated JSON should yield empty map, got %v", got)
	}
}

func TestAdminScopesJSONNestedMaps(t *testing.T) {
	raw := `{"admin@example.com":{"groups":["ops"],"permissions":["users:read"]}}`
	var parsed map[string]map[string][]string
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatal(err)
	}
	if got := parsed["admin@example.com"]["groups"]; len(got) != 1 || got[0] != "ops" {
		t.Fatalf("groups = %v", got)
	}
}
