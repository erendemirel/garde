package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"garde/pkg/config"
)

func initRapid(t *testing.T, value string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rapid_request_config"), []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
}

func TestRapidConfigSingleValueIgnored(t *testing.T) {
	prevThresh, prevTimeout, prevDisabled := RapidRequestThreshold, AutomatedRequestTimeout, rapidRequestCheckDisabled
	t.Cleanup(func() {
		RapidRequestThreshold, AutomatedRequestTimeout, rapidRequestCheckDisabled = prevThresh, prevTimeout, prevDisabled
	})
	initRapid(t, "50")
	InitRapidRequestConfig()
	if RapidRequestThreshold != prevThresh || AutomatedRequestTimeout != prevTimeout {
		t.Fatal("single-value RAPID_REQUEST_CONFIG must be ignored")
	}
	if IsRapidRequestCheckDisabled() != prevDisabled {
		t.Fatal("single-value must not change disabled flag")
	}
}

func TestRapidConfigPartialZeroThreshold(t *testing.T) {
	prevThresh, prevTimeout, prevDisabled := RapidRequestThreshold, AutomatedRequestTimeout, rapidRequestCheckDisabled
	t.Cleanup(func() {
		RapidRequestThreshold, AutomatedRequestTimeout, rapidRequestCheckDisabled = prevThresh, prevTimeout, prevDisabled
	})
	initRapid(t, "0,5")
	InitRapidRequestConfig()
	// Zero threshold is not applied (must be > 0); positive timeout is.
	if RapidRequestThreshold != prevThresh {
		t.Fatalf("threshold = %d, want unchanged %d", RapidRequestThreshold, prevThresh)
	}
	if AutomatedRequestTimeout != 5*time.Millisecond {
		t.Fatalf("timeout = %v, want 5ms", AutomatedRequestTimeout)
	}
	if IsRapidRequestCheckDisabled() {
		t.Fatal("partial config must not disable checking")
	}
}

func TestRapidConfigInvalidKeepsDefaults(t *testing.T) {
	prevThresh, prevTimeout, prevDisabled := RapidRequestThreshold, AutomatedRequestTimeout, rapidRequestCheckDisabled
	t.Cleanup(func() {
		RapidRequestThreshold, AutomatedRequestTimeout, rapidRequestCheckDisabled = prevThresh, prevTimeout, prevDisabled
	})
	initRapid(t, "bogus")
	InitRapidRequestConfig()
	if RapidRequestThreshold != prevThresh || AutomatedRequestTimeout != prevTimeout {
		t.Fatal("invalid value mutated thresholds")
	}
	if IsRapidRequestCheckDisabled() != prevDisabled {
		t.Fatal("invalid value changed disabled flag")
	}
}
