package middleware

import (
	"os"
	"path/filepath"
	"testing"

	"garde/pkg/config"
)

func TestNewRateLimiterZeroDisablesAllTiers(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rate_limit"), []byte("0,0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}

	rl := NewRateLimiter(nil)
	if rl.maxReqs != 0 {
		t.Fatalf("maxReqs=%d want 0", rl.maxReqs)
	}
	if rl.authenticatedMaxReqs != 0 {
		t.Fatalf("authenticatedMaxReqs=%d want 0", rl.authenticatedMaxReqs)
	}
	if rl.adminMaxReqs != 0 {
		t.Fatalf("adminMaxReqs=%d want 0", rl.adminMaxReqs)
	}
	if !IsRateLimitDisabled() {
		t.Fatal("IsRateLimitDisabled() want true for 0,0")
	}
}

func TestIsRateLimitDisabled(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rate_limit"), []byte("100,60"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}

	if IsRateLimitDisabled() {
		t.Fatal("IsRateLimitDisabled() want false for 100,60")
	}
}
