package session

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateSessionIDShape(t *testing.T) {
	id, err := GenerateSessionID()
	if err != nil {
		t.Fatal(err)
	}
	// 64 bytes -> RawURLEncoding, no padding -> 86 chars.
	if len(id) != 86 {
		t.Fatalf("len = %d, want 86", len(id))
	}
	for _, r := range id {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			t.Fatalf("session id %q contains non-base64url rune %q", id, r)
		}
	}
}

func TestGenerateSessionIDUnique(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 100; i++ {
		id, err := GenerateSessionID()
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[id]; dup {
			t.Fatal("duplicate session id, RNG may be broken")
		}
		seen[id] = struct{}{}
	}
}

func TestHashStringDeterministic(t *testing.T) {
	a, b := HashString("10.0.0.1"), HashString("10.0.0.1")
	if a != b {
		t.Fatal("same input hashes differently")
	}
	if len(a) != 64 {
		t.Fatalf("len = %d, want 64 (sha256 hex)", len(a))
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Fatalf("not hex: %v", err)
	}
	if HashString("10.0.0.2") == a {
		t.Fatal("distinct inputs collide")
	}
	if strings.ContainsAny(a, "+/=") {
		t.Fatalf("hash %q is not safe for Redis key suffixes", a)
	}
}
