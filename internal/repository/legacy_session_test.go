package repository

import (
	"context"
	"testing"
	"time"

	"garde/internal/testutil"
	"garde/pkg/session"
)

// Legacy blobs (pre separate-key storage) carry password_hash / mfa_secret
// inline. First read migrates them to dedicated keys; the JSON blob itself is
// left alone.
func TestLegacyCredentialMigration(t *testing.T) {
	testutil.InitConfig(t, map[string]string{"mfa_encryption_key": "test-key-for-unit-tests"})
	ctx := context.Background()
	_, client := testutil.NewMiniRedis(t)
	r := NewRedisRepositoryFromClient(client)

	legacy := `{"id":"legacy-1","email":"legacy@example.com","status":"ok","password_hash":"HASH","mfa_secret":"PLAINSECRET"}`
	if err := client.Set(ctx, "user:legacy-1", legacy, 0).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.Set(ctx, "email_to_id:legacy@example.com", "legacy-1", 0).Err(); err != nil {
		t.Fatal(err)
	}

	got, err := r.GetUserByID(ctx, "legacy-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash != "HASH" {
		t.Fatalf("password = %q", got.PasswordHash)
	}
	if got.MFASecret != "PLAINSECRET" {
		t.Fatalf("mfa = %q", got.MFASecret)
	}
	if v := client.Get(ctx, "user_password:legacy-1").Val(); v != "HASH" {
		t.Fatalf("migrated password key = %q", v)
	}
	if v := client.Get(ctx, "user_mfa:legacy-1").Val(); v == "" || v == "PLAINSECRET" {
		t.Fatalf("migrated mfa key = %q, want encrypted", v)
	}
}

func TestUserActiveSessionsTracksStoreAndDelete(t *testing.T) {
	ctx := context.Background()
	r := newSecRepo(t)
	data := &session.SessionData{UserID: "u-act", IP: "h", UserAgent: "u", CreatedAt: time.Now()}

	sessions, err := r.GetUserActiveSessions(ctx, "u-act")
	if err != nil || len(sessions) != 0 {
		t.Fatalf("initial = %v, %v", sessions, err)
	}
	for _, id := range []string{"s-1", "s-2"} {
		if err := r.StoreSessionData(ctx, id, data, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	sessions, err = r.GetUserActiveSessions(ctx, "u-act")
	if err != nil || len(sessions) != 2 {
		t.Fatalf("after store = %v, %v", sessions, err)
	}
	if err := r.DeleteSession(ctx, "s-1"); err != nil {
		t.Fatal(err)
	}
	sessions, err = r.GetUserActiveSessions(ctx, "u-act")
	if err != nil || len(sessions) != 1 || sessions[0] != "s-2" {
		t.Fatalf("after delete = %v, %v", sessions, err)
	}
}
