package mail

import (
	"crypto/tls"
	"fmt"
	"os"

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

// Rename the original function to defaultSendMail
func defaultSendMail(to, subject, body string) error {
	// Get SMTP configuration from environment variables
	smtpHost := os.Getenv("SMTP_HOST")
	if smtpHost == "" {
		return fmt.Errorf("SMTP_HOST environment variable is not set")
	}

	smtpPortStr := os.Getenv("SMTP_PORT")
	if smtpPortStr == "" {
		smtpPortStr = "587" // Default to TLS port
	}
	smtpPort := smtpPortStr

	smtpUser := os.Getenv("SMTP_USER")
	smtpPassword := os.Getenv("SMTP_PASSWORD")
	from := os.Getenv("SMTP_FROM")
	if from == "" {
		return fmt.Errorf("SMTP_FROM environment variable is not set")
	}

	// Format email message
	msg := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n"+
		"%s", from, to, subject, body)

	// Connect with TLS
	client, err := smtp.DialStartTLS(
		fmt.Sprintf("%s:%s", smtpHost, smtpPort),
		&tls.Config{
			ServerName: smtpHost,
			MinVersion: tls.VersionTLS12,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to connect to mail server")
	}
	defer client.Close()

	// Authenticate if credentials are provided
	if smtpUser != "" && smtpPassword != "" {
		auth := sasl.NewPlainClient("", smtpUser, smtpPassword)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("failed to authenticate with mail server")
		}
	}

	// Set sender and recipients
	if err := client.Mail(from, nil); err != nil {
		return fmt.Errorf("failed to set sender")
	}
	if err := client.Rcpt(to, nil); err != nil {
		return fmt.Errorf("failed to add recipient")
	}

	// Send the email
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
