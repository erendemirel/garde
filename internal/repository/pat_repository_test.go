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

	if err := repo.TouchPAT(ctx, id); err != nil {
		t.Fatalf("TouchPAT: %v", err)
	}
	touched, err := repo.GetPAT(ctx, id)
	if err != nil || touched.LastUsedAt == nil {
		t.Fatalf("last-used not recorded: err=%v token=%+v", err, touched)
	}
}
