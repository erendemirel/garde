package models

import (
	"os"
	"path/filepath"
	"testing"

	"garde/pkg/config"
)

func TestResponseConstructors(t *testing.T) {
	ok := NewSuccessResponse(map[string]string{"k": "v"})
	if ok.Data == nil {
		t.Fatal("success data lost")
	}
	empty := NewSuccessResponse(nil)
	if empty.Data != nil {
		t.Fatal("nil data not preserved")
	}
	errResp := NewErrorResponse("boom")
	if errResp.Error() != "boom" {
		t.Fatalf("Error() = %q", errResp.Error())
	}
	if errResp.Details.Message != "boom" {
		t.Fatalf("message = %q", errResp.Details.Message)
	}
}

func initModelConfig(t *testing.T, secrets map[string]string) {
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

func TestUserResponseIsUserAdmin(t *testing.T) {
	initModelConfig(t, map[string]string{
		"admin_users_json": `{"boss@example.com":"Pw1!"}`,
	})
	if !(&UserResponse{Email: "boss@example.com"}).IsUserAdmin() {
		t.Fatal("listed admin not recognised")
	}
	if (&UserResponse{Email: "peon@example.com"}).IsUserAdmin() {
		t.Fatal("unlisted user recognised as admin")
	}
	initModelConfig(t, map[string]string{})
	if (&UserResponse{Email: "boss@example.com"}).IsUserAdmin() {
		t.Fatal("admin recognised with no admin map configured")
	}
}
