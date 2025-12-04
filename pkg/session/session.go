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
	SessionIDLength          = 64 // = 512 bits
	SessionDuration          = 1 * time.Hour
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

// Default thresholds
const (
	DefaultRapidRequestThreshold   = 120                   // requests per minute
	DefaultAutomatedRequestTimeout = 10 * time.Millisecond // too fast for human
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
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
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
	return base64.URLEncoding.EncodeToString(bytes), nil
}
