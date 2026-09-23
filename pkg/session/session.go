package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"garde/pkg/config"
)

const (
	SessionIDLength = 64 // = 512 bits
	// SessionDuration is the default idle sliding window. Prefer IdleTimeout()
	// so Vault overrides (SESSION_IDLE_TIMEOUT) apply.
	SessionDuration = DefaultSessionIdleTimeout
	// DefaultSessionIdleTimeout: Redis TTL and cookie MaxAge are refreshed on
	// each successful validation, up to this length of inactivity.
	DefaultSessionIdleTimeout = 12 * time.Hour
	// DefaultSessionAbsoluteTimeout: hard ceiling from CreatedAt; no amount of
	// activity extends past this.
	DefaultSessionAbsoluteTimeout = 24 * time.Hour
	// DefaultSessionMaxActive caps concurrent sessions per user (global). Use
	// SESSION_MAX_ACTIVE=0 for unlimited.
	DefaultSessionMaxActive  = 10
	BlacklistPrefix          = "blacklist:"
	BlacklistDuration        = 24 * time.Hour // How long to keep track of revoked sessions
	FailedLoginPrefix        = "failed_login:"
	FailedLoginThreshold     = 5
	FailedLoginBlockDuration = 30 * time.Minute
	IPBlockPrefix            = "ip_block:"
	// Activity Types
	ActivityFailedLogin       = "failed_login"
	ActivityPasswordMismatch  = "password_mismatch"
	ActivityRapidRequests     = "rapid_requests"
	ActivityUnusualUserAgent  = "unusual_user_agent"
	ActivityAutomatedBehavior = "automated_behavior"
)

// Default thresholds for rapid-request detection.
const (
	DefaultRapidRequestThreshold   = 120                   // requests per RapidRequestWindow
	DefaultAutomatedRequestTimeout = 10 * time.Millisecond // too fast for human
	// RapidRequestWindow is the sliding window for rapid-request detection.
	// Distinct from RATE_LIMIT, which uses a configurable window via RATE_LIMIT secrets.
	RapidRequestWindow = time.Minute
)

var (
	RapidRequestThreshold     int64         = DefaultRapidRequestThreshold
	AutomatedRequestTimeout   time.Duration = DefaultAutomatedRequestTimeout
	rapidRequestCheckDisabled bool          = false
)

// This happens when RAPID_REQUEST_CONFIG is set to "0,0"
func IsRapidRequestCheckDisabled() bool {
	return rapidRequestCheckDisabled
}

// Format: "threshold,timeout_ms" e.g. "50,100" means 50 req/min and 100ms timeout
// Use "0,0" to disable rapid request checking entirely
func InitRapidRequestConfig() {
	configValue := config.Get("RAPID_REQUEST_CONFIG")
	if configValue == "" {
		return
	}

	parts := strings.Split(configValue, ",")
	if len(parts) >= 2 {
		threshold, err1 := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		timeoutMs, err2 := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)

		// If both are 0, disable rapid request checking
		if err1 == nil && err2 == nil && threshold == 0 && timeoutMs == 0 {
			rapidRequestCheckDisabled = true
			return
		}

		if err1 == nil && threshold > 0 {
			RapidRequestThreshold = threshold
		}
		if err2 == nil && timeoutMs > 0 {
			AutomatedRequestTimeout = time.Duration(timeoutMs) * time.Millisecond
		}
	} else if len(parts) == 1 {
		if threshold, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64); err == nil && threshold > 0 {
			RapidRequestThreshold = threshold
		}
	}
}

type SessionData struct {
	UserID    string    `json:"user_id"`
	IP        string    `json:"ip"`         // hashed — auth binding only
	UserAgent string    `json:"user_agent"` // hashed — auth binding only
	CreatedAt time.Time `json:"created_at"`
	// Sliding activity; updated on each successful validation.
	LastSeenAt time.Time `json:"last_seen_at,omitempty"`
	// Opaque id for list/revoke APIs (never the raw session secret).
	PublicID string `json:"public_id,omitempty"`
	// Non-secret display metadata (not used for auth checks).
	IPDisplay string `json:"ip_display,omitempty"` // coarse / masked IP
	UAFamily  string `json:"ua_family,omitempty"`
	UASummary string `json:"ua_summary,omitempty"`
	// DeviceKind is desktop | mobile | tool | unknown for UI icons.
	DeviceKind string `json:"device_kind,omitempty"`
}

// IdleTimeout is the sliding inactivity window (default 12h). Override with
// SESSION_IDLE_TIMEOUT (Go duration, e.g. 12h).
func IdleTimeout() time.Duration {
	return durationSecret("SESSION_IDLE_TIMEOUT", DefaultSessionIdleTimeout)
}

// AbsoluteTimeout is the hard max lifetime from CreatedAt (default 24h).
// Override with SESSION_ABSOLUTE_TIMEOUT. Never shorter than IdleTimeout.
func AbsoluteTimeout() time.Duration {
	abs := durationSecret("SESSION_ABSOLUTE_TIMEOUT", DefaultSessionAbsoluteTimeout)
	idle := IdleTimeout()
	if abs < idle {
		return idle
	}
	return abs
}

// IsAbsolutelyExpired reports whether createdAt is past AbsoluteTimeout.
func IsAbsolutelyExpired(createdAt time.Time) bool {
	return time.Since(createdAt) > AbsoluteTimeout()
}

// RemainingTTL is how long Redis/cookie should live after a successful touch:
// min(idle window, time left until absolute expiry). Zero if already expired.
func RemainingTTL(createdAt time.Time) time.Duration {
	left := AbsoluteTimeout() - time.Since(createdAt)
	if left <= 0 {
		return 0
	}
	idle := IdleTimeout()
	if idle < left {
		return idle
	}
	return left
}

// MaxActive is the global concurrent-session cap per user. Override with
// SESSION_MAX_ACTIVE (integer). 0 disables the cap. Invalid values fall back
// to DefaultSessionMaxActive.
func MaxActive() int {
	raw := strings.TrimSpace(config.Get("SESSION_MAX_ACTIVE"))
	if raw == "" {
		return DefaultSessionMaxActive
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return DefaultSessionMaxActive
	}
	return n
}

func durationSecret(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(config.Get(key))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

func IDPrefix(id string) string {
	const n = 10
	if len(id) <= n {
		return id
	}
	return id[:n]
}

func HashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

func GenerateSessionID() (string, error) {
	bytes := make([]byte, SessionIDLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Raw URL-safe base64 (no padding) → 86 characters for 64 bytes.
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
