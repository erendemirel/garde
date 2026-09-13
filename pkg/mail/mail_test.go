package mail

import (
	"testing"

	"garde/internal/testutil"
)

func TestSendMailUsesInjectedFunc(t *testing.T) {
	var gotTo, gotSubject, gotBody string
	prev := SendMailFunc
	t.Cleanup(func() { SendMailFunc = prev })
	SendMailFunc = func(to, subject, body string) error {
		gotTo, gotSubject, gotBody = to, subject, body
		return nil
	}
	if err := SendMail("a@example.com", "hi", "body"); err != nil {
		t.Fatal(err)
	}
	if gotTo != "a@example.com" || gotSubject != "hi" || gotBody != "body" {
		t.Fatalf("mock got to=%q subject=%q body=%q", gotTo, gotSubject, gotBody)
	}
}

func TestDefaultSendMailMissingHost(t *testing.T) {
	// SMTP_FROM present so the failure is attributed to the host, and no
	// network dial is attempted on this path.
	testutil.InitConfig(t, map[string]string{"smtp_from": "from@example.com"})
	if err := defaultSendMail("a@example.com", "hi", "body"); err == nil {
		t.Fatal("expected error with SMTP_HOST unset, got nil (would dial network)")
	}
}

func TestDefaultSendMailMissingFrom(t *testing.T) {
	testutil.InitConfig(t, map[string]string{
		"smtp_host": "smtp.example.com",
		"smtp_port": "587",
	})
	if err := defaultSendMail("a@example.com", "hi", "body"); err == nil {
		t.Fatal("expected error with SMTP_FROM unset, got nil")
	}
}

func TestSanitizeHeaderValueStripsCRLF(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello", "hello"},
		{"cr", "a\rb", "ab"},
		{"lf", "a\nb", "ab"},
		{"crlf injection", "victim@example.com\r\nBcc: attacker@example.com", "victim@example.comBcc: attacker@example.com"},
		{"subject", "hi\r\nSubject: evil", "hiSubject: evil"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeHeaderValue(tc.in); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
