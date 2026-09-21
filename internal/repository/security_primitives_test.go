package repository

import (
	"context"
	"testing"
	"time"

	"garde/internal/models"
	"garde/pkg/session"
)

// Second-wave repository coverage: the security primitives around users and
// sessions. Ephemeral paths run on miniredis; durable user listing needs Postgres.
func newSecRepo(t *testing.T) *RedisRepository {
	t.Helper()
	return NewRedisRepositoryFromClient(newMiniRedisClient(t))
}

func newDurableSecRepo(t *testing.T) *RedisRepository {
	t.Helper()
	return newDurableStore(t)
}

func TestBlockAndCheckIP(t *testing.T) {
	ctx := context.Background()
	r := newSecRepo(t)
	blocked, err := r.IsIPBlocked(ctx, "10.0.0.9")
	if err != nil || blocked {
		t.Fatalf("blocked = %v, %v; want false", blocked, err)
	}
	if err := r.BlockIP(ctx, "10.0.0.9", time.Minute); err != nil {
		t.Fatal(err)
	}
	blocked, err = r.IsIPBlocked(ctx, "10.0.0.9")
	if err != nil || !blocked {
		t.Fatalf("blocked = %v, %v; want true", blocked, err)
	}
	if blocked, _ := r.IsIPBlocked(ctx, "10.0.0.10"); blocked {
		t.Fatal("unrelated IP blocked")
	}
}

func TestFailedLoginCountsAndClear(t *testing.T) {
	ctx := context.Background()
	r := newSecRepo(t)
	for want := int64(1); want <= 2; want++ {
		n, err := r.RecordFailedLogin(ctx, "victim@example.com", "10.0.0.1")
		if err != nil || n != want {
			t.Fatalf("attempt %d: n=%d err=%v", want, n, err)
		}
	}
	got, err := r.GetFailedLoginCount(ctx, "victim@example.com", "10.0.0.1")
	if err != nil || got != 2 {
		t.Fatalf("GetFailedLoginCount = %d err=%v, want 2", got, err)
	}
	ipOnly, err := r.GetFailedLoginCount(ctx, "", "10.0.0.1")
	if err != nil || ipOnly != 2 {
		t.Fatalf("GetFailedLoginCount IP-only = %d err=%v, want 2", ipOnly, err)
	}
	if err := r.ClearFailedLogins(ctx, "victim@example.com", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	got, err = r.GetFailedLoginCount(ctx, "victim@example.com", "10.0.0.1")
	if err != nil || got != 0 {
		t.Fatalf("after clear GetFailedLoginCount = %d err=%v", got, err)
	}
	n, err := r.RecordFailedLogin(ctx, "victim@example.com", "10.0.0.1")
	if err != nil || n != 1 {
		t.Fatalf("after clear: n=%d err=%v", n, err)
	}
}

func TestSuspiciousActivityAndAuditLog(t *testing.T) {
	ctx := context.Background()
	r := newSecRepo(t)
	if err := r.RecordSuspiciousActivity(ctx, "u-1", "failed_login",
		map[string]string{"ip": "10.0.0.1"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n := r.getClient().LLen(ctx, "suspicious_activity:u-1").Val(); n != 1 {
		t.Fatalf("suspicious len = %d, want 1", n)
	}
	if err := r.RecordAuditLog(ctx, "u-1", map[string]any{"action": "login"}, 10, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n := r.getClient().LLen(ctx, "audit_log:u-1").Val(); n != 1 {
		t.Fatalf("audit len = %d, want 1", n)
	}
}

func TestLastRequestTimeRoundTrip(t *testing.T) {
	ctx := context.Background()
	r := newSecRepo(t)
	zero, err := r.GetLastRequestTime(ctx, "u-1")
	if err != nil || !zero.IsZero() {
		t.Fatalf("unset = %v, %v; want zero", zero, err)
	}
	before := time.Now().Add(-time.Second)
	if err := r.UpdateLastRequestTime(ctx, "u-1", time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetLastRequestTime(ctx, "u-1")
	if err != nil || got.Before(before) || got.After(time.Now().Add(time.Second)) {
		t.Fatalf("got = %v, %v", got, err)
	}
}

func TestActiveSessionInfoLifecycle(t *testing.T) {
	ctx := context.Background()
	r := newSecRepo(t)
	found, _, err := r.GetActiveSessionInfo(ctx, "u-1")
	if err != nil || found {
		t.Fatalf("found = %v, %v; want false", found, err)
	}
	data := &session.SessionData{UserID: "u-1", IP: "ip-hash", UserAgent: "ua", CreatedAt: time.Now()}
	if err := r.StoreSessionData(ctx, "sess-active", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	found, ip, err := r.GetActiveSessionInfo(ctx, "u-1")
	if err != nil || !found || ip != "ip-hash" {
		t.Fatalf("found = %v ip = %q err = %v", found, ip, err)
	}
}

func TestClearUserSecurityData(t *testing.T) {
	ctx := context.Background()
	r := newSecRepo(t)
	if _, err := r.RecordFailedLogin(ctx, "clear@example.com", "10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateLastRequestTime(ctx, "u-clear", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.ClearUserSecurityData(ctx, "u-clear", "clear@example.com", "10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"failed_login:clear@example.com",
		"last_request:u-clear",
	} {
		if n := r.getClient().Exists(ctx, key).Val(); n != 0 {
			t.Fatalf("key %s still present", key)
		}
	}
	// Empty identifiers are a safe no-op, never a full-table delete.
	if err := r.ClearUserSecurityData(ctx, "", "", ""); err != nil {
		t.Fatalf("empty clear: %v", err)
	}
}

func TestPingAndDeleteKey(t *testing.T) {
	ctx := context.Background()
	r := newSecRepo(t)
	if err := r.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := r.DeleteKey(ctx, "ephemeral"); err != nil {
		t.Fatalf("delete missing key: %v", err)
	}
	if err := r.StoreSecurityCode(ctx, "u-1", "123456"); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteKey(ctx, "security_code:u-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetSecurityCode(ctx, "u-1"); err == nil {
		t.Fatal("deleted security code still readable")
	}
}

func TestSecurityCodeRoundTrip(t *testing.T) {
	ctx := context.Background()
	r := newSecRepo(t)
	if err := r.StoreSecurityCode(ctx, "u-1", "654321"); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetSecurityCode(ctx, "u-1")
	if err != nil || got != "654321" {
		t.Fatalf("code = %q, %v", got, err)
	}
}

func TestTempMFASecretRoundTrip(t *testing.T) {
	initTestConfig(t, map[string]string{"mfa_encryption_key": "test-key-for-unit-tests"})
	ctx := context.Background()
	r := newSecRepo(t)
	if err := r.StoreTempMFASecret(ctx, "u-1", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetTempMFASecret(ctx, "u-1")
	if err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("temp = %q, %v", got, err)
	}
	if err := r.DeleteTempMFASecret(ctx, "u-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetTempMFASecret(ctx, "u-1"); err == nil {
		t.Fatal("deleted temp secret still readable")
	}
}

func TestGetLockedUsersFilters(t *testing.T) {
	ctx := context.Background()
	r := newDurableSecRepo(t)
	mk := func(id, email string, status models.UserStatus) {
		t.Helper()
		if err := r.StoreUser(ctx, &models.User{ID: id, Email: email, Status: status}); err != nil {
			t.Fatal(err)
		}
	}
	mk("u-ok", "ok@example.com", models.UserStatusOk)
	mk("u-locked", "locked@example.com", models.UserStatusLockedBySecurity)
	mk("u-pending", "pending@example.com", models.UserStatusPendingApproval)

	locked, err := r.GetLockedUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, u := range locked {
		ids[u.ID] = true
	}
	if !ids["u-locked"] || !ids["u-pending"] {
		t.Fatalf("locked set = %v, want u-locked + u-pending", ids)
	}
	if ids["u-ok"] {
		t.Fatalf("ok user in locked set: %v", ids)
	}
}

func TestGetAllUsersListsStored(t *testing.T) {
	ctx := context.Background()
	r := newDurableSecRepo(t)
	for _, u := range [][2]string{{"u-a", "a@example.com"}, {"u-b", "b@example.com"}} {
		if err := r.StoreUser(ctx, &models.User{ID: u[0], Email: u[1], Status: models.UserStatusOk}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := r.GetAllUsers(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("all = %d, %v", len(all), err)
	}
}

func TestGetGroupByIDAndAllGroups(t *testing.T) {
	repo, err := NewPermissionRepository(newTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	ctx := context.Background()
	g, err := repo.CreateGroup(ctx, "core", "core team")
	if err != nil {
		t.Fatal(err)
	}
	byID, err := repo.GetGroupByID(ctx, g.ID)
	if err != nil || byID.Name != "core" {
		t.Fatalf("by id = %+v, %v", byID, err)
	}
	all, err := repo.GetAllGroups(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("all = %v, %v", all, err)
	}
	vis, err := repo.GetAllPermissionVisibility(ctx)
	if err != nil || len(vis) != 0 {
		t.Fatalf("visibility = %v, %v", vis, err)
	}
}
