package config

import "strings"

// CapLoginFailureThreshold is how many failed login attempts (email or IP)
// must already be recorded before Cap is required on /login. 1 means the
// first try is free; the second try needs a solved challenge.
const CapLoginFailureThreshold int64 = 1

// CapEnabled reports whether Cap challenge verification is active for public
// auth routes. Requires an explicit enable flag plus site key, secret, and API URL.
func CapEnabled() bool {
	if !GetBool("CAP_ENABLED") {
		return false
	}
	return CapSiteKey() != "" && CapSecretKey() != "" && CapAPIURL() != ""
}

// CapSiteKey is the public Cap site key used by the widget and siteverify path.
func CapSiteKey() string {
	return strings.TrimSpace(Get("CAP_SITE_KEY"))
}

// CapSecretKey is the Cap key secret used only for server-side siteverify.
func CapSecretKey() string {
	return strings.TrimSpace(Get("CAP_SECRET_KEY"))
}

// CapAPIURL is the Cap Standalone base URL used by garde for siteverify
// (typically the internal compose hostname, e.g. http://cap:3000).
func CapAPIURL() string {
	return strings.TrimRight(strings.TrimSpace(Get("CAP_API_URL")), "/")
}

// CapPublicURL is the Cap Standalone base URL browsers use for the widget and
// dashboard (e.g. http://localhost:3000 or https://cap.example.com).
func CapPublicURL() string {
	return strings.TrimRight(strings.TrimSpace(Get("CAP_PUBLIC_URL")), "/")
}

// CapWidgetEndpoint is the full Cap API endpoint the widget should call:
// {public_url}/{site_key}/
func CapWidgetEndpoint() string {
	public := CapPublicURL()
	siteKey := CapSiteKey()
	if public == "" || siteKey == "" {
		return ""
	}
	return public + "/" + siteKey + "/"
}

// CapBypassToken is an optional local/e2e-only token accepted instead of a real
// Cap siteverify response. Leave empty in production.
func CapBypassToken() string {
	return strings.TrimSpace(Get("CAP_BYPASS_TOKEN"))
}
