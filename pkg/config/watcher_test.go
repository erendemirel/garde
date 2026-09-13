package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Watcher lifecycle only: start on an initialised loader, observe a reload
// hook firing on change, then stop. Event timing comes from fsnotify, so the
// test polls with a deadline instead of sleeping a fixed span.
func TestWatcherStartReloadStop(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "answer"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(StopWatcher)

	reloaded := make(chan struct{}, 1)
	SetReloadHook(func() { reloaded <- struct{}{} })
	t.Cleanup(func() { SetReloadHook(nil) })

	if err := StartWatcher(); err != nil {
		t.Fatalf("start: %v", err)
	}
	// Second start replaces the watcher; must not error either.
	if err := StartWatcher(); err != nil {
		t.Fatalf("restart: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "answer"), []byte("2"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloaded:
	case <-time.After(5 * time.Second):
		t.Fatal("reload hook did not fire within 5s")
	}
	if got := Get("answer"); got != "2" {
		t.Fatalf("reloaded value = %q, want 2", got)
	}
	StopWatcher()
}

func TestStopWatcherNilSafe(t *testing.T) {
	withSecrets(t, map[string]string{})
	StopWatcher()
	StopWatcher()
}
