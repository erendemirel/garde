package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"garde/pkg/config"

	"github.com/gin-gonic/gin"
)

func mtlsCert(t *testing.T, cn string, sans []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              sans,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func serveMTLS(t *testing.T, cert *x509.Certificate) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(MTLSMiddleware())
	router.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if cert != nil {
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
			VerifiedChains:   [][]*x509.Certificate{{cert}},
		}
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec.Code
}

func TestMTLSMiddlewareTable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "domain_name"), []byte("example.com"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}

	if code := serveMTLS(t, nil); code != http.StatusUnauthorized {
		t.Fatalf("no cert: status = %d", code)
	}
	if code := serveMTLS(t, mtlsCert(t, "example.com", nil)); code != http.StatusOK {
		t.Fatalf("exact CN: status = %d", code)
	}
	if code := serveMTLS(t, mtlsCert(t, "other.com", []string{"example.com"})); code != http.StatusOK {
		t.Fatalf("exact SAN: status = %d", code)
	}
	if code := serveMTLS(t, mtlsCert(t, "unrelated.com", nil)); code != http.StatusUnauthorized {
		t.Fatalf("mismatch: status = %d", code)
	}
	// Pinned audit finding: the CN fallback reduces to the last two labels,
	// so a sibling subdomain currently passes. If this ever fails, the
	// finding was fixed — update the audit note and this test together.
	if code := serveMTLS(t, mtlsCert(t, "attacker.example.com", nil)); code != http.StatusOK {
		t.Fatalf("sibling subdomain: status = %d, want 200 (known over-permissive)", code)
	}
}
