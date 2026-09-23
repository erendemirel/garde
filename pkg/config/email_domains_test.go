package config

import (
	"testing"
)

func TestEmailDomainListsEmptyByDefault(t *testing.T) {
	withSecrets(t, map[string]string{})
	if EmailDomainPolicyConfigured() {
		t.Fatal("expected no domain policy when unset")
	}
	if !EmailDomainPermitted("anyone@example.com") {
		t.Fatal("empty policy should permit any valid-looking email")
	}
}

func TestEmailDomainAllowlistAndBlocklist(t *testing.T) {
	withSecrets(t, map[string]string{
		"email_allowed_domains": "example.com, *.corp.example",
		"email_blocked_domains": "blocked.example.com, *.tempmail.test",
	})

	cases := []struct {
		email string
		want  bool
	}{
		{"user@example.com", true},
		{"user@EXAMPLE.COM", true},
		{"user@mail.example.com", false}, // apex allow does not include subdomains
		{"user@a.corp.example", true},
		{"user@a.b.corp.example", true},
		{"user@corp.example", false}, // wildcard does not match apex
		{"user@blocked.example.com", false},
		{"user@x.tempmail.test", false},
		{"user@other.com", false},
	}
	for _, tc := range cases {
		if got := EmailDomainPermitted(tc.email); got != tc.want {
			t.Fatalf("EmailDomainPermitted(%q) = %v, want %v", tc.email, got, tc.want)
		}
	}
}

func TestEmailDomainBlocklistWinsOverAllowlist(t *testing.T) {
	withSecrets(t, map[string]string{
		"email_allowed_domains": "*.example.com",
		"email_blocked_domains": "bad.example.com",
	})
	if EmailDomainPermitted("ok@good.example.com") != true {
		t.Fatal("expected allowed subdomain")
	}
	if EmailDomainPermitted("x@bad.example.com") {
		t.Fatal("blocklist should win")
	}
}

func TestEmailDomainBlocklistOnly(t *testing.T) {
	withSecrets(t, map[string]string{
		"email_blocked_domains": "spam.test, *.disposable.test",
	})
	if !EmailDomainPermitted("user@example.com") {
		t.Fatal("unlisted domains should pass when only blocklist is set")
	}
	if EmailDomainPermitted("a@spam.test") {
		t.Fatal("exact block should reject")
	}
	if EmailDomainPermitted("x@y.disposable.test") {
		t.Fatal("wildcard block should reject")
	}
}

func TestValidateEmailDomainLists(t *testing.T) {
	withSecrets(t, map[string]string{
		"email_allowed_domains": "example.com, *.corp.com",
	})
	if err := ValidateEmailDomainLists(); err != nil {
		t.Fatalf("valid lists: %v", err)
	}

	bad := []string{"*", "*.", "foo.*.com", "@example.com", "user@example.com", "-bad.com", "bad-.com", "..com"}
	for _, p := range bad {
		withSecrets(t, map[string]string{"email_allowed_domains": p})
		if err := ValidateEmailDomainLists(); err == nil {
			t.Fatalf("pattern %q should be rejected", p)
		}
	}
}

func TestParseEmailDomainListDedupTrim(t *testing.T) {
	got := parseEmailDomainList(" Example.COM , example.com, *.Corp.COM , ")
	if len(got) != 2 || got[0] != "example.com" || got[1] != "*.corp.com" {
		t.Fatalf("got %#v", got)
	}
}
