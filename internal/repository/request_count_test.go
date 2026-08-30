package repository

import (
	"context"
	"testing"
	"time"

	"garde/pkg/session"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
)

func newTestRepo(t *testing.T) (*RedisRepository, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return &RedisRepository{client: client}, mr
}

func TestRequestCountSlidingWindow(t *testing.T) {
	repo, mr := newTestRepo(t)
	ctx := context.Background()
	id := "user-1"
	window := time.Minute

	for i := 0; i < 5; i++ {
		if err := repo.IncrementRequestCount(ctx, id, window); err != nil {
			t.Fatalf("increment %d: %v", i, err)
		}
	}
	count, err := repo.GetRequestCount(ctx, id, window)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if count != 5 {
		t.Fatalf("count = %d, want 5", count)
	}

	// Advance past the window — entries should drop out of the sliding window
	mr.FastForward(window + time.Second)
	count, err = repo.GetRequestCount(ctx, id, window)
	if err != nil {
		t.Fatalf("get after forward: %v", err)
	}
	if count != 0 {
		t.Fatalf("count after window = %d, want 0", count)
	}
}

func TestRequestCountRateLimitAndRapidRequestKeysIsolated(t *testing.T) {
	repo, _ := newTestRepo(t)
	ctx := context.Background()
	window := 30 * time.Second

	if err := repo.IncrementRequestCount(ctx, "rate_limit:1.2.3.4", window); err != nil {
		t.Fatal(err)
	}
	if err := repo.IncrementRequestCount(ctx, "user-abc", session.RapidRequestWindow); err != nil {
		t.Fatal(err)
	}

	ipCount, err := repo.GetRequestCount(ctx, "rate_limit:1.2.3.4", window)
	if err != nil {
		t.Fatal(err)
	}
	userCount, err := repo.GetRequestCount(ctx, "user-abc", session.RapidRequestWindow)
	if err != nil {
		t.Fatal(err)
	}
	if ipCount != 1 || userCount != 1 {
		t.Fatalf("ip=%d user=%d, want both 1", ipCount, userCount)
	}
}

func TestUserSessionIndex(t *testing.T) {
	repo, _ := newTestRepo(t)
	ctx := context.Background()
	userID := "u1"
	sid1 := "sess-1"
	sid2 := "sess-2"

	data1 := &session.SessionData{UserID: userID, IP: session.HashString("1.1.1.1"), UserAgent: "ua", CreatedAt: time.Now()}
	data2 := &session.SessionData{UserID: userID, IP: session.HashString("2.2.2.2"), UserAgent: "ua", CreatedAt: time.Now()}

	if err := repo.StoreSessionData(ctx, sid1, data1, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := repo.StoreSessionData(ctx, sid2, data2, time.Hour); err != nil {
		t.Fatal(err)
	}

	sessions, err := repo.GetUserActiveSessions(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions = %v, want 2", sessions)
	}

	has, ip, err := repo.GetActiveSessionInfo(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if !has || ip == "" {
		t.Fatalf("active session info: has=%v ip=%q", has, ip)
	}

	if err := repo.DeleteSession(ctx, sid1); err != nil {
		t.Fatal(err)
	}
	sessions, err = repo.GetUserActiveSessions(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0] != sid2 {
		t.Fatalf("after delete: %v", sessions)
	}
}
