package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// PublicIDBytes is the size of the opaque session id returned to clients.
const PublicIDBytes = 16

// NewSessionData builds session state for a fresh login. Hashes are used for
// auth binding; display fields are non-secret metadata for the sessions UI.
func NewSessionData(userID, ip, userAgent string) (*SessionData, error) {
	publicID, err := GeneratePublicID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	family, summary, kind := SummarizeUserAgent(userAgent)
	return &SessionData{
		UserID:     userID,
		IP:         HashString(ip),
		UserAgent:  HashString(userAgent),
		CreatedAt:  now,
		LastSeenAt: now,
		PublicID:   publicID,
		IPDisplay:  MaskIP(ip),
		UAFamily:   family,
		UASummary:  summary,
		DeviceKind: kind,
	}, nil
}

// GeneratePublicID returns a random opaque id safe to expose in list/revoke APIs.
func GeneratePublicID() (string, error) {
	b := make([]byte, PublicIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session public id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// MaskIP returns a coarse location hint: IPv4 /24-style (last octet x),
// IPv6 /48-style truncation. Not a city — no geo database required.
func MaskIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(ip)
	if err == nil {
		ip = host
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "unknown"
	}
	if v4 := parsed.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.x", v4[0], v4[1], v4[2])
	}
	// IPv6: keep first 3 hextets.
	parts := strings.Split(parsed.String(), ":")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], ":") + ":…"
	}
	return parsed.String()
}

// SummarizeUserAgent extracts a rough browser/OS label and device kind for display.
// Kind is one of: desktop, mobile, tool (curl/postman/script), unknown.
func SummarizeUserAgent(ua string) (family, summary, kind string) {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return "Unknown", "Unknown client", "unknown"
	}
	lower := strings.ToLower(ua)

	family = "Browser"
	kind = "desktop"
	switch {
	case strings.Contains(lower, "edg/"):
		family = "Edge"
	case strings.Contains(lower, "chrome/") && !strings.Contains(lower, "chromium"):
		family = "Chrome"
	case strings.Contains(lower, "chromium"):
		family = "Chromium"
	case strings.Contains(lower, "firefox/"):
		family = "Firefox"
	case strings.Contains(lower, "safari/") && !strings.Contains(lower, "chrome"):
		family = "Safari"
	case strings.Contains(lower, "opera") || strings.Contains(lower, "opr/"):
		family = "Opera"
	case strings.Contains(lower, "curl/"):
		family = "curl"
		kind = "tool"
	case strings.Contains(lower, "postman"):
		family = "Postman"
		kind = "tool"
	case strings.Contains(lower, "python-requests") || strings.Contains(lower, "go-http-client"):
		family = "Script"
		kind = "tool"
	}

	osName := "unknown OS"
	switch {
	case strings.Contains(lower, "windows"):
		osName = "Windows"
	case strings.Contains(lower, "android"):
		osName = "Android"
		if kind != "tool" {
			kind = "mobile"
		}
	case strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad"):
		osName = "iOS"
		if kind != "tool" {
			kind = "mobile"
		}
	case strings.Contains(lower, "mac os") || strings.Contains(lower, "macintosh"):
		osName = "macOS"
	case strings.Contains(lower, "linux"):
		osName = "Linux"
	default:
		if kind != "tool" {
			kind = "unknown"
		}
	}

	return family, family + " on " + osName, kind
}

// TouchDisplay updates last-seen and ensures a PublicID exists for older sessions.
func (d *SessionData) TouchDisplay() error {
	if d == nil {
		return nil
	}
	d.LastSeenAt = time.Now().UTC()
	if d.PublicID == "" {
		id, err := GeneratePublicID()
		if err != nil {
			return err
		}
		d.PublicID = id
	}
	if d.UAFamily == "" && d.UASummary == "" {
		d.UAFamily = "Unknown"
		d.UASummary = "Unknown client"
	}
	if d.DeviceKind == "" {
		d.DeviceKind = InferDeviceKind(d.UAFamily, d.UASummary)
	}
	if d.IPDisplay == "" {
		d.IPDisplay = "unknown"
	}
	return nil
}

// InferDeviceKind maps stored family/summary to a UI device kind when DeviceKind
// was not persisted (older sessions).
func InferDeviceKind(family, summary string) string {
	f := strings.ToLower(strings.TrimSpace(family))
	s := strings.ToLower(strings.TrimSpace(summary))
	switch f {
	case "curl", "postman", "script":
		return "tool"
	case "unknown", "":
		return "unknown"
	}
	if strings.Contains(s, "android") || strings.Contains(s, "ios") {
		return "mobile"
	}
	if strings.Contains(s, "windows") || strings.Contains(s, "macos") || strings.Contains(s, "linux") {
		return "desktop"
	}
	if strings.Contains(s, "unknown") {
		return "unknown"
	}
	return "desktop"
}
