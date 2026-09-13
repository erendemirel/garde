package crypto

import (
	"testing"
)

func TestPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("DevAdminTest123!")
	if err != nil {
		t.Fatal(err)
	}
	if hash == "" {
		t.Fatal("empty hash")
	}
	ok, err := VerifyPassword("DevAdminTest123!", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("correct password does not verify")
	}
}

func TestPasswordWrongIsFalse(t *testing.T) {
	hash, err := HashPassword("DevAdminTest123!")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword("WrongPassword1!", hash)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("wrong password verifies")
	}
}

func TestPasswordSaltsUnique(t *testing.T) {
	a, err := HashPassword("SamePassword1!")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPassword("SamePassword1!")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("identical hashes for the same password, salt may be reused")
	}
}

// Malformed inputs must answer false, never panic (regression: decoded[:16]
// on a short slice panicked with an index out of range).
func TestPasswordMalformedHashes(t *testing.T) {
	for name, hash := range map[string]string{
		"empty":     "",
		"short":     "c2hvcnQ=",
		"garbage":   "!!!not-base64!!!",
		"truncated": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="[:40],
	} {
		t.Run(name, func(t *testing.T) {
			ok, err := VerifyPassword("anything1!", hash)
			if err == nil && hash == "!!!not-base64!!!" {
				t.Fatal("expected decode error for non-base64 input")
			}
			if ok {
				t.Fatalf("malformed hash %q verifies", hash)
			}
		})
	}
}
