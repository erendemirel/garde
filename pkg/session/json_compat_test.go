package session

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Go 1.27 backs encoding/json with v2 while preserving v1 API semantics.
// These fixtures lock SessionData shapes stored in Redis against silent drift.

func TestSessionDataJSONRoundTrip(t *testing.T) {
	in := SessionData{
		UserID:    "user-äβγ-001",
		IP:        "2001:db8::1",
		UserAgent: "Mozilla/5.0 (compatible; garde-test/1.0)",
		CreatedAt: time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC),
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out SessionData
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.UserID != in.UserID || out.IP != in.IP || out.UserAgent != in.UserAgent {
		t.Fatalf("round-trip mismatch: %+v vs %+v", in, out)
	}
	if !out.CreatedAt.Equal(in.CreatedAt) {
		t.Fatalf("CreatedAt = %v, want %v", out.CreatedAt, in.CreatedAt)
	}
}

func TestSessionDataJSONRejectsTruncated(t *testing.T) {
	err := json.Unmarshal([]byte(`{"user_id":"x","ip":`), &SessionData{})
	if err == nil {
		t.Fatal("expected error on truncated JSON")
	}
}

func TestSessionDataJSONUnknownFieldsIgnored(t *testing.T) {
	// v1 encoding/json ignores unknown fields; v2-backed v1 API must keep that.
	raw := []byte(`{"user_id":"u1","ip":"127.0.0.1","user_agent":"ua","created_at":"2026-01-02T03:04:05Z","extra":"ignore-me"}`)
	var out SessionData
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.UserID != "u1" || out.IP != "127.0.0.1" {
		t.Fatalf("unexpected decode: %+v", out)
	}
}

func TestSessionDataJSONDoesNotEmitEmptyAsNullMaps(t *testing.T) {
	raw, err := json.Marshal(SessionData{UserID: "u"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if strings.Contains(s, `"password"`) {
		t.Fatalf("unexpected sensitive field: %s", s)
	}
	if !strings.Contains(s, `"user_id":"u"`) {
		t.Fatalf("missing user_id: %s", s)
	}
}
