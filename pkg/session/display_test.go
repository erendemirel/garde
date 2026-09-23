package session

import (
	"strings"
	"testing"
)

func TestMaskIP(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"203.0.113.45", "203.0.113.x"},
		{"203.0.113.45:443", "203.0.113.x"},
		{"", "unknown"},
		{"not-an-ip", "unknown"},
	}
	for _, tc := range cases {
		if got := MaskIP(tc.in); got != tc.want {
			t.Fatalf("MaskIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	v6 := MaskIP("2001:db8:85a3::8a2e:370:7334")
	if !strings.HasSuffix(v6, ":…") || !strings.HasPrefix(v6, "2001:db8:85a3") {
		t.Fatalf("MaskIP IPv6 = %q", v6)
	}
}

func TestSummarizeUserAgent(t *testing.T) {
	family, summary, kind := SummarizeUserAgent(
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	)
	if family != "Chrome" || summary != "Chrome on Windows" || kind != "desktop" {
		t.Fatalf("got %q / %q / %q", family, summary, kind)
	}
	family, summary, kind = SummarizeUserAgent(
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
	)
	if kind != "mobile" {
		t.Fatalf("iphone kind = %q, want mobile (family=%q summary=%q)", kind, family, summary)
	}
	_, _, kind = SummarizeUserAgent("curl/8.0")
	if kind != "tool" {
		t.Fatalf("curl kind = %q, want tool", kind)
	}
	family, summary, kind = SummarizeUserAgent("")
	if family != "Unknown" || summary != "Unknown client" || kind != "unknown" {
		t.Fatalf("empty UA: %q / %q / %q", family, summary, kind)
	}
}

func TestNewSessionData(t *testing.T) {
	d, err := NewSessionData("u1", "10.0.0.5", "Mozilla/5.0 (Macintosh) Firefox/120.0")
	if err != nil {
		t.Fatal(err)
	}
	if d.PublicID == "" || len(d.PublicID) != PublicIDBytes*2 {
		t.Fatalf("PublicID = %q", d.PublicID)
	}
	if d.IP != HashString("10.0.0.5") || d.IPDisplay != "10.0.0.x" {
		t.Fatalf("IP fields: hash=%q display=%q", d.IP, d.IPDisplay)
	}
	if d.UAFamily != "Firefox" || !strings.Contains(d.UASummary, "macOS") {
		t.Fatalf("UA: %q / %q", d.UAFamily, d.UASummary)
	}
	if d.DeviceKind != "desktop" {
		t.Fatalf("DeviceKind = %q, want desktop", d.DeviceKind)
	}
	if d.LastSeenAt.IsZero() || d.CreatedAt.IsZero() {
		t.Fatal("timestamps unset")
	}
}
