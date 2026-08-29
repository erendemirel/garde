package models_test

import (
	"encoding/json"
	"testing"

	"garde/internal/models"
)

func TestUserJSONOmitsSensitiveFields(t *testing.T) {
	u := &models.User{
		ID:           "user-1",
		Email:        "a@b.com",
		PasswordHash: "should-not-appear",
		MFASecret:    "should-not-appear-either",
		Status:       models.UserStatusOk,
	}
	raw, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		t.Fatal(err)
	}
	if _, ok := asMap["password_hash"]; ok {
		t.Fatalf("password_hash must not be serialized: %s", raw)
	}
	if _, ok := asMap["mfa_secret"]; ok {
		t.Fatalf("mfa_secret must not be serialized: %s", raw)
	}
	if _, ok := asMap["pending_updates"]; !ok {
		t.Fatalf("pending_updates should be present even when nil: %s", raw)
	}
}

func TestParseLegacyCredentials(t *testing.T) {
	raw := []byte(`{"id":"1","password_hash":"ph","mfa_secret":"ms"}`)
	ph, ms := models.ParseLegacyCredentials(raw)
	if ph != "ph" || ms != "ms" {
		t.Fatalf("got %q %q", ph, ms)
	}
}
