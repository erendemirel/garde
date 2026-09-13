package models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHasPermission(t *testing.T) {
	u := &User{Permissions: UserPermissions{"read": true, "write": false}}
	if !u.HasPermission("read") {
		t.Fatal("enabled permission reports false")
	}
	if u.HasPermission("write") {
		t.Fatal("disabled permission reports true")
	}
	if u.HasPermission("missing") {
		t.Fatal("absent permission reports true")
	}
	if (&User{}).HasPermission("read") {
		t.Fatal("nil map reports true")
	}
}

func TestIsValidUserStatus(t *testing.T) {
	for _, s := range []UserStatus{
		UserStatusOk, UserStatusLockedByAdmin, UserStatusLockedBySecurity,
		UserStatusPendingApproval, UserStatusApprovalRejected,
	} {
		if !IsValidUserStatus(s) {
			t.Fatalf("status %q reports invalid", s)
		}
	}
	for _, s := range []UserStatus{"", "active", "OK", "locked"} {
		if IsValidUserStatus(s) {
			t.Fatalf("status %q reports valid", s)
		}
	}
}

func TestSharesAnyUserGroup(t *testing.T) {
	a := UserGroups{"A": true, "B": false}
	b := UserGroups{"B": true, "C": true}
	c := UserGroups{"A": true}
	if SharesAnyUserGroup(a, b) {
		t.Fatal("B disabled in A but reported shared")
	}
	if !SharesAnyUserGroup(a, c) {
		t.Fatal("shared enabled group A not detected")
	}
	if SharesAnyUserGroup(UserGroups{}, c) {
		t.Fatal("empty groups report shared")
	}
	if SharesAnyUserGroup(nil, nil) {
		t.Fatal("nil groups report shared")
	}
}

// Password hashes and MFA secrets live in dedicated Redis keys, never in the
// user JSON blob. A regression here leaks credentials into logs/backups.
func TestUserJSONOmitsSecrets(t *testing.T) {
	u := &User{
		ID:           "id-1",
		Email:        "a@example.com",
		PasswordHash: "HASH",
		MFASecret:    "SECRET",
		Status:       UserStatusOk,
	}
	raw, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "HASH") || strings.Contains(string(raw), "SECRET") {
		t.Fatalf("secrets present in JSON: %s", raw)
	}
	if strings.Contains(string(raw), "password_hash") || strings.Contains(string(raw), "mfa_secret") {
		t.Fatalf("secret keys present in JSON: %s", raw)
	}
}
