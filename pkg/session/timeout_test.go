package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"garde/pkg/config"
)

func writeSecrets(t *testing.T, kv map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for k, v := range kv {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
}

func TestIdleAndAbsoluteDefaults(t *testing.T) {
	writeSecrets(t, map[string]string{})
	if IdleTimeout() != DefaultSessionIdleTimeout {
		t.Fatalf("IdleTimeout = %v, want %v", IdleTimeout(), DefaultSessionIdleTimeout)
	}
	if AbsoluteTimeout() != DefaultSessionAbsoluteTimeout {
		t.Fatalf("AbsoluteTimeout = %v, want %v", AbsoluteTimeout(), DefaultSessionAbsoluteTimeout)
	}
}

func TestTimeoutSecretsOverride(t *testing.T) {
	writeSecrets(t, map[string]string{
		"session_idle_timeout":     "30m",
		"session_absolute_timeout": "2h",
	})
	if IdleTimeout() != 30*time.Minute {
		t.Fatalf("IdleTimeout = %v, want 30m", IdleTimeout())
	}
	if AbsoluteTimeout() != 2*time.Hour {
		t.Fatalf("AbsoluteTimeout = %v, want 2h", AbsoluteTimeout())
	}
}

func TestAbsoluteNotShorterThanIdle(t *testing.T) {
	writeSecrets(t, map[string]string{
		"session_idle_timeout":     "8h",
		"session_absolute_timeout": "1h",
	})
	if AbsoluteTimeout() != 8*time.Hour {
		t.Fatalf("AbsoluteTimeout = %v, want clamped to idle 8h", AbsoluteTimeout())
	}
}

func TestRemainingTTLAndAbsoluteExpiry(t *testing.T) {
	writeSecrets(t, map[string]string{
		"session_idle_timeout":     "1h",
		"session_absolute_timeout": "3h",
	})
	now := time.Now()
	if RemainingTTL(now) != time.Hour {
		t.Fatalf("fresh RemainingTTL = %v, want 1h", RemainingTTL(now))
	}
	nearAbs := now.Add(-2*time.Hour - 30*time.Minute)
	got := RemainingTTL(nearAbs)
	if got < 25*time.Minute || got > 35*time.Minute {
		t.Fatalf("near-absolute RemainingTTL = %v, want ~30m", got)
	}
	if !IsAbsolutelyExpired(now.Add(-4 * time.Hour)) {
		t.Fatal("expected absolute expiry")
	}
	if RemainingTTL(now.Add(-4*time.Hour)) != 0 {
		t.Fatal("expired RemainingTTL want 0")
	}
}

func TestMaxActiveSecret(t *testing.T) {
	writeSecrets(t, map[string]string{})
	if MaxActive() != DefaultSessionMaxActive {
		t.Fatalf("default MaxActive = %d, want %d", MaxActive(), DefaultSessionMaxActive)
	}
	writeSecrets(t, map[string]string{"session_max_active": "3"})
	if MaxActive() != 3 {
		t.Fatalf("MaxActive = %d, want 3", MaxActive())
	}
	writeSecrets(t, map[string]string{"session_max_active": "0"})
	if MaxActive() != 0 {
		t.Fatalf("MaxActive = %d, want 0 (unlimited)", MaxActive())
	}
}
