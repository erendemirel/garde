package mail

import (
	"crypto/tls"
	"fmt"
	"garde/pkg/config"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

var (
	// Allows mocking of SendMail for testing
	SendMailFunc = defaultSendMail
)

func SendMail(to, subject, body string) error {
	return SendMailFunc(to, subject, body)
}

func sanitizeHeaderValue(v string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, v)
}

func defaultSendMail(to, subject, body string) error {
	smtpHost := config.Get("SMTP_HOST")
	if smtpHost == "" {
		return fmt.Errorf("SMTP_HOST is not set")
	}

	smtpPort := config.GetWithDefault("SMTP_PORT", "587")

	smtpUser := config.Get("SMTP_USER")
	smtpPassword := config.Get("SMTP_PASSWORD")
	from := config.Get("SMTP_FROM")
	if from == "" {
		return fmt.Errorf("SMTP_FROM environment variable is not set")
	}

	to = sanitizeHeaderValue(to)
	subject = sanitizeHeaderValue(subject)
	from = sanitizeHeaderValue(from)

	msg := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"\r\n"+
		"%s", from, to, subject, body)

	addr := net.JoinHostPort(smtpHost, smtpPort)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to mail server")
	}
	_ = rawConn.SetDeadline(time.Now().Add(30 * time.Second))

	client, err := smtp.NewClientStartTLS(rawConn, &tls.Config{
		ServerName: smtpHost,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		_ = rawConn.Close()
		return fmt.Errorf("failed to connect to mail server")
	}
	defer client.Close()

	if smtpUser != "" && smtpPassword != "" {
		auth := sasl.NewPlainClient("", smtpUser, smtpPassword)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("failed to authenticate with mail server")
		}
	}

	if err := client.Mail(from, nil); err != nil {
		return fmt.Errorf("failed to set sender")
	}
	if err := client.Rcpt(to, nil); err != nil {
		return fmt.Errorf("failed to add recipient")
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to start data")
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("failed to write body")
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close data")
	}

	return nil
}
