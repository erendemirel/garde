package config

import (
	"fmt"
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
	t.Cleanup(func() {
		SetReloadHook(nil)
		SetReloadValidator(nil)
	})

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

func TestWatcherReloadRejectedRestoresPrior(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("good"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(StopWatcher)

	SetReloadValidator(func() error {
		if Get("TOKEN") == "bad" {
			return fmt.Errorf("rejected")
		}
		return nil
	})
	reloaded := make(chan struct{}, 1)
	SetReloadHook(func() { reloaded <- struct{}{} })
	t.Cleanup(func() {
		SetReloadHook(nil)
		SetReloadValidator(nil)
	})

	if err := StartWatcher(); err != nil {
		t.Fatalf("start: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloaded:
		t.Fatal("reload hook fired for a rejected secret update")
	case <-time.After(2 * time.Second):
	}
	if got := Get("TOKEN"); got != "good" {
		t.Fatalf("after reject = %q, want good", got)
	}

	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("better"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloaded:
	case <-time.After(5 * time.Second):
		t.Fatal("valid reload hook did not fire within 5s")
	}
	if got := Get("TOKEN"); got != "better" {
		t.Fatalf("after accept = %q, want better", got)
	}
	StopWatcher()
}

func TestStopWatcherNilSafe(t *testing.T) {
	withSecrets(t, map[string]string{})
	StopWatcher()
	StopWatcher()
}
