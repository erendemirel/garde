package testutil

import (
	"context"
	"testing"

	"garde/pkg/config"
)

// Helpers dogfood the conventions: seed config, round-trip a Redis key.
func TestInitConfigAndMiniRedis(t *testing.T) {
	InitConfig(t, map[string]string{"answer": "42"})
	if got := config.Get("ANSWER"); got != "42" {
		t.Fatalf("config = %q, want 42 (loader uppercases filenames)", got)
	}

	_, client := NewMiniRedis(t)
	ctx := context.Background()
	if err := client.Set(ctx, "k", "v", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if got, err := client.Get(ctx, "k").Result(); err != nil || got != "v" {
		t.Fatalf("round-trip = %q, %v; want v, nil", got, err)
	}
}
