package repository

import (
	"context"
	"testing"
	"time"

	"garde/internal/models"
	"garde/pkg/crypto"
)

func TestPATStoreListRevoke(t *testing.T) {
	repo, _ := newTestRepo(t)
	ctx := context.Background()

	_, id, hash, err := crypto.GeneratePAT()
	if err != nil {
		t.Fatal(err)
	}
	token := &models.PersonalAccessToken{
		ID:         id,
		UserID:     "user-1",
		Name:       "ci",
		SecretHash: hash,
		CreatedAt:  time.Now().UTC(),
	}
	if err := repo.StorePAT(ctx, token); err != nil {
		t.Fatalf("StorePAT: %v", err)
	}

	got, err := repo.GetPAT(ctx, id)
	if err != nil {
		t.Fatalf("GetPAT: %v", err)
	}
	if got.Name != "ci" || got.UserID != "user-1" {
		t.Fatalf("unexpected token: %+v", got)
	}

	list, err := repo.ListPATsByUser(ctx, "user-1")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListPATsByUser: err=%v len=%d", err, len(list))
	}

	if n, err := repo.CountPATsByUser(ctx, "user-1"); err != nil || n != 1 {
		t.Fatalf("CountPATsByUser: err=%v n=%d", err, n)
	}

	if _, err := repo.RevokePAT(ctx, id, "other-user"); err == nil {
		t.Fatal("revoke by wrong user must fail")
	}

	revoked, err := repo.RevokePAT(ctx, id, "user-1")
	if err != nil {
		t.Fatalf("RevokePAT: %v", err)
	}
	if !revoked.Revoked() {
		t.Fatal("expected revoked")
	}

	if n, err := repo.CountPATsByUser(ctx, "user-1"); err != nil || n != 0 {
		t.Fatalf("revoked tokens must not consume the cap: err=%v n=%d", err, n)
	}
	if list, err := repo.ListPATsByUser(ctx, "user-1"); err != nil || len(list) != 0 {
		t.Fatalf("list must omit revoked tokens: err=%v len=%d", err, len(list))
	}
	// Record kept so auth can still resolve and refuse the secret.
	if kept, err := repo.GetPAT(ctx, id); err != nil || !kept.Revoked() {
		t.Fatalf("revoked record must remain: err=%v token=%+v", err, kept)
	}

	if err := repo.TouchPAT(ctx, id); err != nil {
		t.Fatalf("TouchPAT: %v", err)
	}
	touched, err := repo.GetPAT(ctx, id)
	if err != nil || touched.LastUsedAt == nil {
		t.Fatalf("last-used not recorded: err=%v token=%+v", err, touched)
	}
}

// Issue/revoke cycles must not permanently fill MaxPATsPerUser.
func TestPATCountIgnoresRevokedAfterCycles(t *testing.T) {
	repo, _ := newTestRepo(t)
	ctx := context.Background()

	for i := 0; i < models.MaxPATsPerUser+3; i++ {
		_, id, hash, err := crypto.GeneratePAT()
		if err != nil {
			t.Fatal(err)
		}
		token := &models.PersonalAccessToken{
			ID:         id,
			UserID:     "user-1",
			Name:       "cycle",
			SecretHash: hash,
			CreatedAt:  time.Now().UTC(),
		}
		if err := repo.StorePAT(ctx, token); err != nil {
			t.Fatalf("StorePAT %d: %v", i, err)
		}
		if _, err := repo.RevokePAT(ctx, id, "user-1"); err != nil {
			t.Fatalf("RevokePAT %d: %v", i, err)
		}
		n, err := repo.CountPATsByUser(ctx, "user-1")
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("after cycle %d count = %d, want 0", i, n)
		}
	}
}
