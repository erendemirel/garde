package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"

	"garde/pkg/config"
)

// Build loads the server keypair and maps a client-certificate policy onto the handshake.
//
// "Off" is not the same as "no client CA". When a CA is configured, a certificate
// that is presented is still verified — that is what allows /validate to demand
// mTLS while browsers on the same listener present nothing.
func Build(certPath, keyPath, caPath string, policy config.ClientCertPolicy, surface string) (*tls.Config, error) {
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("%s listener needs both a certificate and a key path", surface)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load the %s server certificate: %w", surface, err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
	}

	if caPath != "" {
		caCertPool := x509.NewCertPool()
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read the %s client CA: %w", surface, err)
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("no usable certificate in the %s client CA at %s", surface, caPath)
		}

		if block, _ := pem.Decode(caCert); block != nil {
			if parsed, err := x509.ParseCertificate(block.Bytes); err == nil {
				slog.Info("Loaded client CA", "surface", surface, "subject", parsed.Subject, "issuer", parsed.Issuer)
			}
		}

		tlsConfig.ClientCAs = caCertPool
		if policy == config.ClientCertRequired {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			// Verify client certs when presented; do not require them on every
			// connection.
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
	} else if policy != config.ClientCertOff {
		return nil, fmt.Errorf("%s listener asks for client certificates but no client CA is configured", surface)
	}

	if len(cert.Certificate) > 0 {
		if x509Cert, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			slog.Info("Server using certificate", "surface", surface, "subject", x509Cert.Subject, "issuer", x509Cert.Issuer)
		}
	}

	return tlsConfig, nil
}
