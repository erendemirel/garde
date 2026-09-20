package tlsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"garde/pkg/config"
)

// Go 1.25→1.27 risk locks for TLS:
// - LoadX509KeyPair always populates Certificate.Leaf (x509keypairleaf removed)
// - MinVersion stays TLS 1.2 (tls10server default change is permanent)
// - ClientAuth policy mapping for optional vs required CA
// - Handshake matrix under VerifyClientCertIfGiven / RequireAndVerifyClientCert

func writePEM(t *testing.T, path string, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

func writeKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path, "EC PRIVATE KEY", der)
}

type testCertMaterial struct {
	dir        string
	caCert     *x509.Certificate
	caKey      *ecdsa.PrivateKey
	serverCert string
	serverKey  string
	caPath     string
}

func issueCert(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, tmpl *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func newTestMaterial(t *testing.T) testCertMaterial {
	t.Helper()
	dir := t.TempDir()

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "garde-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caCert, caKey := issueCert(t, nil, nil, caTmpl)

	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverCert, serverKey := issueCert(t, caCert, caKey, serverTmpl)

	caPath := filepath.Join(dir, "ca.pem")
	serverCertPath := filepath.Join(dir, "server.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	writePEM(t, caPath, "CERTIFICATE", caCert.Raw)
	writePEM(t, serverCertPath, "CERTIFICATE", serverCert.Raw)
	writeKey(t, serverKeyPath, serverKey)

	return testCertMaterial{
		dir:        dir,
		caCert:     caCert,
		caKey:      caKey,
		serverCert: serverCertPath,
		serverKey:  serverKeyPath,
		caPath:     caPath,
	}
}

func (m testCertMaterial) clientCert(t *testing.T, sans []string) tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "client"},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cert, key := issueCert(t, m.caCert, m.caKey, tmpl)
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

func TestBuildRequiresCertAndKey(t *testing.T) {
	_, err := Build("", "key.pem", "", config.ClientCertOff, "public")
	if err == nil {
		t.Fatal("expected error when cert path missing")
	}
	_, err = Build("cert.pem", "", "", config.ClientCertOff, "public")
	if err == nil {
		t.Fatal("expected error when key path missing")
	}
}

func TestBuildRequiresCAWhenPolicyDemandsClientCerts(t *testing.T) {
	m := newTestMaterial(t)
	_, err := Build(m.serverCert, m.serverKey, "", config.ClientCertRequired, "service")
	if err == nil {
		t.Fatal("expected error when required policy has no CA")
	}
	_, err = Build(m.serverCert, m.serverKey, "", config.ClientCertOptional, "public")
	if err == nil {
		t.Fatal("expected error when optional policy has no CA")
	}
}

func TestBuildPopulatesLeafAndMinTLS12(t *testing.T) {
	// Go 1.27: x509keypairleaf GODEBUG removed — Leaf must always be set.
	m := newTestMaterial(t)
	cfg, err := Build(m.serverCert, m.serverKey, "", config.ClientCertOff, "public")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %#x, want TLS1.2", cfg.MinVersion)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("ClientAuth = %v, want NoClientCert", cfg.ClientAuth)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates len = %d", len(cfg.Certificates))
	}
	if cfg.Certificates[0].Leaf == nil {
		t.Fatal("LoadX509KeyPair must populate Certificate.Leaf (Go 1.27 permanent behavior)")
	}
	if cfg.Certificates[0].Leaf.Subject.CommonName != "localhost" {
		t.Fatalf("Leaf CN = %q", cfg.Certificates[0].Leaf.Subject.CommonName)
	}
}

func TestBuildClientAuthPolicyMapping(t *testing.T) {
	m := newTestMaterial(t)

	off, err := Build(m.serverCert, m.serverKey, m.caPath, config.ClientCertOff, "public")
	if err != nil {
		t.Fatal(err)
	}
	// CA present + Off ⇒ still verify if a cert is presented.
	if off.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("off+CA ClientAuth = %v, want VerifyClientCertIfGiven", off.ClientAuth)
	}
	if off.ClientCAs == nil {
		t.Fatal("expected ClientCAs when CA path set")
	}

	optional, err := Build(m.serverCert, m.serverKey, m.caPath, config.ClientCertOptional, "public")
	if err != nil {
		t.Fatal(err)
	}
	if optional.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("optional ClientAuth = %v", optional.ClientAuth)
	}

	required, err := Build(m.serverCert, m.serverKey, m.caPath, config.ClientCertRequired, "service")
	if err != nil {
		t.Fatal(err)
	}
	if required.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("required ClientAuth = %v", required.ClientAuth)
	}
}

func TestHandshakeOptionalAllowsNoClientCert(t *testing.T) {
	m := newTestMaterial(t)
	cfg, err := Build(m.serverCert, m.serverKey, m.caPath, config.ClientCertOff, "public")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		errCh <- nil
	}()

	client := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		ServerName:         "localhost",
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}
	client.RootCAs.AddCert(m.caCert)

	conn, err := tls.Dial("tcp", ln.Addr().String(), client)
	if err != nil {
		t.Fatalf("client handshake without client cert failed: %v", err)
	}
	_, _ = conn.Write([]byte{1})
	_ = conn.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeRequiredRejectsMissingClientCert(t *testing.T) {
	m := newTestMaterial(t)
	cfg, err := Build(m.serverCert, m.serverKey, m.caPath, config.ClientCertRequired, "service")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	handshakeErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			handshakeErr <- err
			return
		}
		defer conn.Close()
		handshakeErr <- conn.(*tls.Conn).Handshake()
	}()

	client := &tls.Config{
		RootCAs:    x509.NewCertPool(),
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
	client.RootCAs.AddCert(m.caCert)

	conn, dialErr := tls.Dial("tcp", ln.Addr().String(), client)
	if conn != nil {
		_ = conn.Close()
	}
	serverErr := <-handshakeErr

	if dialErr == nil && serverErr == nil {
		t.Fatal("expected handshake failure when client cert required but not presented")
	}
}

func TestHandshakeRequiredAcceptsCAIssuedClientCert(t *testing.T) {
	m := newTestMaterial(t)
	cfg, err := Build(m.serverCert, m.serverKey, m.caPath, config.ClientCertRequired, "service")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan *tls.ConnectionState, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- nil
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			done <- nil
			return
		}
		state := tlsConn.ConnectionState()
		done <- &state
		_, _ = io.Copy(io.Discard, conn)
	}()

	clientCert := m.clientCert(t, []string{"example.com"})
	client := &tls.Config{
		RootCAs:      x509.NewCertPool(),
		Certificates: []tls.Certificate{clientCert},
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}
	client.RootCAs.AddCert(m.caCert)

	conn, err := tls.Dial("tcp", ln.Addr().String(), client)
	if err != nil {
		t.Fatalf("mTLS handshake failed: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("ok"))

	state := <-done
	if state == nil {
		t.Fatal("server did not complete handshake")
	}
	if len(state.PeerCertificates) == 0 {
		t.Fatal("server saw no peer certificate")
	}
	if len(state.VerifiedChains) == 0 {
		t.Fatal("server missing VerifiedChains after RequireAndVerifyClientCert")
	}
}

func TestHTTPServerServesOverBuiltTLS(t *testing.T) {
	// End-to-end smoke: tls.Config from Build works with net/http (default PQ KEX).
	m := newTestMaterial(t)
	cfg, err := Build(m.serverCert, m.serverKey, m.caPath, config.ClientCertOff, "public")
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Handler: mux, TLSConfig: cfg, ReadHeaderTimeout: 2 * time.Second}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(m.caCert)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				ServerName: "localhost",
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	resp, err := client.Get("https://" + ln.Addr().String() + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
