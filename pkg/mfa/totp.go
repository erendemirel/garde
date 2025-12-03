package mfa

import (
	"bytes"
	"encoding/base64"
	"image/png"

	"github.com/pquerna/otp/totp"
)

type Key struct {
	Secret     string
	URL        string
	QRCodeData string // Base64 encoded PNG image
}

func GenerateSecret(email string) (*Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "garde",
		AccountName: email,
	})
	if err != nil {
		return nil, err
	}

	// Generate QR code image
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, err
	}

	// Encode as base64 PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	qrBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	return &Key{
		Secret:     key.Secret(),
		URL:        key.URL(),
		QRCodeData: "data:image/png;base64," + qrBase64,
	}, nil
}

func ValidateCode(secret, code string) bool {
	return totp.Validate(code, secret)
}
