package mfa

import (
	"github.com/pquerna/otp/totp"
)

type Key struct {
	Secret string
	URL    string
}

func GenerateSecret(email string) (*Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "YourApp",
		AccountName: email,
	})
	if err != nil {
		return nil, err
	}

	return &Key{
		Secret: key.Secret(),
		URL:    key.URL(),
	}, nil
}

func ValidateCode(secret, code string) bool {
	return totp.Validate(code, secret)
}
