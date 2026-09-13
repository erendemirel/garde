package repository

import (
	"context"
	"testing"
	"time"

	"garde/pkg/session"
)

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
