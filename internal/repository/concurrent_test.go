package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"garde/internal/models"
)

// StoreUser is optimistic: a write based on a stale read is refused instead
// of silently clobbering the newer record.
func TestStoreUserConcurrentUpdateRefused(t *testing.T) {
	ctx := context.Background()
	r := newUserRepo(t)
	original := &models.User{ID: "u-race", Email: "race@example.com", Status: models.UserStatusOk}
	if err := r.StoreUser(ctx, original); err != nil {
		t.Fatal(err)
	}

	fresh, err := r.GetUserByID(ctx, "u-race")
	if err != nil {
		t.Fatal(err)
	}
	stale := *fresh

	// A newer write lands first (bump the clock so After() is unambiguous).
	fresh.Status = models.UserStatusLockedByAdmin
	fresh.UpdatedAt = time.Now().Add(time.Second)
	if err := r.StoreUser(ctx, fresh); err != nil {
		t.Fatal(err)
	}

	stale.Status = models.UserStatusLockedBySecurity
	if err := r.StoreUser(ctx, &stale); !errors.Is(err, ErrConcurrentUpdate) {
		t.Fatalf("stale write err = %v, want ErrConcurrentUpdate", err)
	}
	winner, _ := r.GetUserByID(ctx, "u-race")
	if winner.Status != models.UserStatusLockedByAdmin {
		t.Fatalf("loser overwrote winner: %q", winner.Status)
	}
}
