package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"
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

// Thresholds
const (
	RapidRequestThreshold   = 10                     // requests per minute
	AutomatedRequestTimeout = 100 * time.Millisecond // too fast for human
)

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

// GenerateSessionID creates a cryptographically secure random session ID
func GenerateSessionID() (string, error) {
	bytes := make([]byte, SessionIDLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
