package config

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	EmailAllowedDomainsKey = "EMAIL_ALLOWED_DOMAINS"
	EmailBlockedDomainsKey = "EMAIL_BLOCKED_DOMAINS"
)

// EmailAllowedDomains returns the configured registration allowlist patterns.
// Empty means all domains are allowed (subject to the blocklist).
func EmailAllowedDomains() []string {
	return parseEmailDomainList(Get(EmailAllowedDomainsKey))
}

// EmailBlockedDomains returns the configured registration blocklist patterns.
// Empty means nothing is blocked by domain.
func EmailBlockedDomains() []string {
	return parseEmailDomainList(Get(EmailBlockedDomainsKey))
}

// EmailDomainPolicyConfigured reports whether either list is non-empty.
func EmailDomainPolicyConfigured() bool {
	return len(EmailAllowedDomains()) > 0 || len(EmailBlockedDomains()) > 0
}

// ValidateEmailDomainLists checks pattern syntax for both lists at startup/reload.
func ValidateEmailDomainLists() error {
	for _, p := range EmailAllowedDomains() {
		if err := validateEmailDomainPattern(p); err != nil {
			return fmt.Errorf("%s: %w", EmailAllowedDomainsKey, err)
		}
	}
	for _, p := range EmailBlockedDomains() {
		if err := validateEmailDomainPattern(p); err != nil {
			return fmt.Errorf("%s: %w", EmailBlockedDomainsKey, err)
		}
	}
	return nil
}

// EmailDomainPermitted reports whether the email's domain may register under
// the current allow/block lists. Blocklist wins. Empty allowlist = allow all
// (minus blocklist). Patterns are case-insensitive; `*.example.com` matches
// any subdomain of example.com (not the apex itself).
func EmailDomainPermitted(email string) bool {
	domain := emailDomain(email)
	if domain == "" {
		return false
	}
	blocked := EmailBlockedDomains()
	if domainMatchesAny(domain, blocked) {
		return false
	}
	allowed := EmailAllowedDomains()
	if len(allowed) == 0 {
		return true
	}
	return domainMatchesAny(domain, allowed)
}

func parseEmailDomainList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func emailDomain(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return email[at+1:]
}

func domainMatchesAny(domain string, patterns []string) bool {
	for _, p := range patterns {
		if domainMatchesPattern(domain, p) {
			return true
		}
	}
	return false
}

// domainMatchesPattern supports exact domains and a single leading `*.` wildcard
// that matches one or more subdomain labels (e.g. *.example.com → a.example.com,
// a.b.example.com). The apex (example.com) is not matched by *.example.com.
func domainMatchesPattern(domain, pattern string) bool {
	if pattern == "" || domain == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(domain, suffix) && len(domain) > len(suffix)
	}
	if strings.ContainsRune(pattern, '*') {
		return false
	}
	return domain == pattern
}

func validateEmailDomainPattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("empty pattern")
	}
	if strings.ContainsRune(pattern, '@') {
		return fmt.Errorf("pattern %q must be a domain, not an email address", pattern)
	}
	if pattern == "*" || pattern == "*." {
		return fmt.Errorf("pattern %q is too broad", pattern)
	}

	body := pattern
	if strings.HasPrefix(pattern, "*.") {
		body = pattern[2:]
		if body == "" {
			return fmt.Errorf("pattern %q needs a domain after *.", pattern)
		}
		if strings.ContainsRune(body, '*') {
			return fmt.Errorf("pattern %q may only use a leading *.", pattern)
		}
	} else if strings.ContainsRune(pattern, '*') {
		return fmt.Errorf("pattern %q may only use a leading *.", pattern)
	}

	if strings.HasPrefix(body, ".") || strings.HasSuffix(body, ".") || strings.Contains(body, "..") {
		return fmt.Errorf("pattern %q has an invalid domain shape", pattern)
	}

	labels := strings.Split(body, ".")
	if len(labels) < 1 {
		return fmt.Errorf("pattern %q is not a valid domain", pattern)
	}
	for _, label := range labels {
		if err := validateDomainLabel(label); err != nil {
			return fmt.Errorf("pattern %q: %w", pattern, err)
		}
	}
	return nil
}

func validateDomainLabel(label string) error {
	if label == "" || len(label) > 63 {
		return fmt.Errorf("invalid domain label %q", label)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("domain label %q cannot start or end with a hyphen", label)
	}
	for _, r := range label {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' {
			continue
		}
		return fmt.Errorf("domain label %q has invalid characters", label)
	}
	return nil
}
