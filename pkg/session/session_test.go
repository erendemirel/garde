package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"garde/pkg/config"
)

func TestInitRapidRequestConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rapid_request_config"), []byte("50,25"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}

	prevThresh := RapidRequestThreshold
	prevTimeout := AutomatedRequestTimeout
	prevDisabled := rapidRequestCheckDisabled
	t.Cleanup(func() {
		RapidRequestThreshold = prevThresh
		AutomatedRequestTimeout = prevTimeout
		rapidRequestCheckDisabled = prevDisabled
	})

	InitRapidRequestConfig()
	if RapidRequestThreshold != 50 {
		t.Fatalf("threshold=%d want 50", RapidRequestThreshold)
	}
	if AutomatedRequestTimeout != 25*time.Millisecond {
		t.Fatalf("timeout=%v want 25ms", AutomatedRequestTimeout)
	}
	if IsRapidRequestCheckDisabled() {
		t.Fatal("should not be disabled")
	}
}

func TestInitRapidRequestConfigDisable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rapid_request_config"), []byte("0,0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}

	prevDisabled := rapidRequestCheckDisabled
	t.Cleanup(func() { rapidRequestCheckDisabled = prevDisabled })

	InitRapidRequestConfig()
	if !IsRapidRequestCheckDisabled() {
		t.Fatal("expected disabled")
	}
}

func TestRapidRequestWindowConstant(t *testing.T) {
	if RapidRequestWindow != time.Minute {
		t.Fatalf("RapidRequestWindow=%v want 1m (distinct from RATE_LIMIT configurable window)", RapidRequestWindow)
	}
}
