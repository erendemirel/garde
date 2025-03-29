package integration

import (
	"auth_service/internal/middleware"
	"auth_service/internal/models"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"
)

// TestValidateEndpoint tests the /validate endpoint which requires API key and mTLS authentication
func TestValidateEndpoint(t *testing.T) {
	// Load .env file
	if err := godotenv.Load("../.env"); err != nil {
		t.Fatalf("Error loading .env file: %v", err)
	}

	// Wait for services to be ready
	time.Sleep(5 * time.Second)

	// Set testing mode and domain name for mTLS tests
	os.Setenv("TESTING_MODE", "true")
	os.Setenv("DOMAIN_NAME", "auth-service") // To match the CN in the client cert

	// Print out key environment variables for debugging
	t.Logf("Environment variables:")
	t.Logf("TESTING_MODE: %s", os.Getenv("TESTING_MODE"))
	t.Logf("DOMAIN_NAME: %s", os.Getenv("DOMAIN_NAME"))
	t.Logf("USE_TLS: %s", os.Getenv("USE_TLS"))
	t.Logf("TLS_CERT_PATH: %s", os.Getenv("TLS_CERT_PATH"))
	t.Logf("TLS_KEY_PATH: %s", os.Getenv("TLS_KEY_PATH"))
	t.Logf("TLS_CA_PATH: %s", os.Getenv("TLS_CA_PATH"))

	// Get API key from .env
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		t.Fatal("API_KEY environment variable not set")
	}
	// Print just the first few characters of the API key for debugging
	if len(apiKey) > 8 {
		t.Logf("API_KEY (first 8 chars): %s...", apiKey[:8])
	}

	// Check if TLS is enabled
	useMTLS := strings.ToLower(os.Getenv("USE_TLS")) == "true"
	if !useMTLS {
		t.Fatalf("TestValidateEndpoint requires USE_TLS=true")
	}

	// Use appropriate protocol based on TLS setting
	protocol := "http"
	if useMTLS {
		protocol = "https"
		// Check if certificates exist
		certPath := "../certs/client-cert.pem"
		keyPath := "../certs/client-key.pem"
		caPath := "../certs/ca-cert.pem"

		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			t.Logf("Warning: Client certificate not found at: %s", certPath)
			useMTLS = false
			protocol = "http"
		} else {
			t.Logf("Found client certificate at: %s", certPath)
		}

		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			t.Logf("Warning: Client key not found at: %s", keyPath)
			useMTLS = false
			protocol = "http"
		} else {
			t.Logf("Found client key at: %s", keyPath)
		}

		if _, err := os.Stat(caPath); os.IsNotExist(err) {
			t.Logf("Warning: CA certificate not found at: %s", caPath)
			useMTLS = false
			protocol = "http"
		} else {
			t.Logf("Found CA certificate at: %s", caPath)
		}
	}

	// Get port from environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "8443" // Default port if not specified
	}

	// Determine base URL
	baseURL := fmt.Sprintf("%s://localhost:%s", protocol, port)
	t.Logf("Using base URL: %s", baseURL)

	// Using regular client without TLS for HTTP
	client := &http.Client{}
	if useMTLS {
		// This client will be used for non-mTLS tests
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}

	// ------------------ Create test user and login ------------------
	// Create a new user
	email := fmt.Sprintf("validate_test_user_%d@example.com", time.Now().Unix())
	password := "TestPassword123!"

	// Set up certificate configuration for all clients
	var certConfig *tls.Config
	if useMTLS {
		// Load client certificates
		cert, err := tls.LoadX509KeyPair(
			"../certs/client-cert.pem",
			"../certs/client-key.pem",
		)
		if err != nil {
			t.Fatalf("Failed to load client certificates: %v", err)
		}

		// Log certificate info
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			t.Logf("Using client certificate with CN: %s", x509Cert.Subject.CommonName)
			t.Logf("Certificate issuer: %s", x509Cert.Issuer.CommonName)
			t.Logf("Certificate DNS names: %v", x509Cert.DNSNames)
			t.Logf("Certificate IP addresses: %v", x509Cert.IPAddresses)
		}

		// Load CA certificate
		caCert, err := os.ReadFile("../certs/ca-cert.pem")
		if err != nil {
			t.Fatalf("Failed to load CA cert: %v", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			t.Fatalf("Failed to append CA cert to pool")
		}

		// Create detailed TLS config with more debugging
		certConfig = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caCertPool,
			InsecureSkipVerify: true, // Only for testing
			// Make sure server name is set to match the expected value in the server
			ServerName: "auth-service",
		}
	}

	// Using client with TLS verification disabled for user creation and login
	insecureClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: certConfig,
		},
	}

	createUserReq := models.CreateUserRequest{
		Email:    email,
		Password: password,
	}
	createUserBody, _ := json.Marshal(createUserReq)
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/users", baseURL), bytes.NewBuffer(createUserBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := insecureClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	respBody := logRequestAndResponse(t, req, resp, createUserBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create user, status: %v, body: %s", resp.StatusCode, respBody)
	}
	resp.Body.Close()

	// Login to get a session ID
	loginReq := models.LoginRequest{
		Email:    email,
		Password: password,
	}
	loginBody, _ := json.Marshal(loginReq)
	req, _ = http.NewRequest("POST", fmt.Sprintf("%s/login", baseURL), bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = insecureClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	respBody = logRequestAndResponse(t, req, resp, loginBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to login, status: %v, body: %s", resp.StatusCode, respBody)
	}

	var loginResp models.SuccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("Failed to decode login response: %v, body: %s", err, respBody)
	}
	loginData := loginResp.Data.(map[string]interface{})
	sessionID := loginData["session_id"].(string)
	resp.Body.Close()

	t.Logf("Created user with email %s and got session ID: %s", email, sessionID)

	// ------------------ Test cases for /validate endpoint ------------------
	t.Run("Without mTLS: Validate session with API key only", func(t *testing.T) {
		// Skip this test when mTLS is enabled, as the server will reject non-mTLS connections
		if useMTLS {
			t.Skip("Skipping non-mTLS test when mTLS is enabled")
		}

		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/validate?session_id=%s", baseURL, sessionID), nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(middleware.APIKeyHeader, apiKey)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		respBody := logRequestAndResponse(t, req, resp, nil)

		// Without mTLS, expect 401 instead of 200
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected status 401 without mTLS, got: %v, body: %s", resp.StatusCode, respBody)
		}
	})

	// Only run the mTLS test if mTLS is configured and certificates exist
	if useMTLS {
		t.Run("With mTLS: Validate session with API key and certificates", func(t *testing.T) {
			// Create TLS configuration with client certificates
			// Use the same certificate config created earlier
			tlsConfig := certConfig

			// Add VerifyPeerCertificate callback for debugging
			tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				t.Logf("TLS handshake occurring - verifiedChains length: %d", len(verifiedChains))
				return nil
			}

			// Create client with TLS config
			mtlsClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
					// Force use of TLS1.2 or higher
					TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
				},
			}

			// Create request - make sure API key is properly formatted
			req, _ := http.NewRequest("GET", fmt.Sprintf("%s/validate?session_id=%s", baseURL, sessionID), nil)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(middleware.APIKeyHeader, apiKey) // Make sure this EXACTLY matches the format expected
			// Add Authorization header with Bearer token
			req.Header.Set(middleware.AuthHeaderKey, middleware.SessionPrefix+sessionID)

			// Print the exact API key value for debugging
			t.Logf("Using API key: '%s'", apiKey)
			t.Logf("API key header name: '%s'", middleware.APIKeyHeader)
			t.Logf("Using session ID in Authorization header: '%s'", sessionID)
			t.Logf("All request headers: %v", req.Header)

			// Log the request before sending
			t.Logf("Sending mTLS request to %s with API key and Authorization header", req.URL.String())

			resp, err := mtlsClient.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			respBody := logRequestAndResponse(t, req, resp, nil)

			// With proper mTLS we expect a 200 OK
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("Expected status 200, got: %v, body: %s", resp.StatusCode, respBody)
			}

			// Parse the response
			var validateResp models.SuccessResponse
			if err := json.NewDecoder(resp.Body).Decode(&validateResp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			// Check that the session is valid - with a safer approach to avoid panic
			data, ok := validateResp.Data.(map[string]interface{})
			if !ok {
				t.Fatalf("Response data not in expected format: %v", validateResp.Data)
			}

			responseObj, ok := data["Response"].(map[string]interface{})
			if !ok {
				t.Fatalf("Response object not in expected format: %v", data["Response"])
			}

			valid, ok := responseObj["valid"].(bool)
			if !ok {
				t.Fatalf("Valid field not in expected format: %v", responseObj["valid"])
			}

			if !valid {
				t.Fatalf("Expected session to be valid, got invalid: %v", validateResp)
			}
		})
	} else {
		t.Log("Skipping mTLS success test since TLS is not enabled or certificates not found")
	}

	t.Run("Failure: Missing API key", func(t *testing.T) {
		// Create a client with mTLS configuration
		mtlsClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: certConfig,
			},
		}

		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/validate?session_id=%s", baseURL, sessionID), nil)
		req.Header.Set("Content-Type", "application/json")
		// No API key set

		resp, err := mtlsClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		respBody := logRequestAndResponse(t, req, resp, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected status 401, got: %v, body: %s", resp.StatusCode, respBody)
		}
	})

	t.Run("Failure: Invalid API key", func(t *testing.T) {
		// Create a client with mTLS configuration
		mtlsClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: certConfig,
			},
		}

		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/validate?session_id=%s", baseURL, sessionID), nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(middleware.APIKeyHeader, "invalid-api-key")

		resp, err := mtlsClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		respBody := logRequestAndResponse(t, req, resp, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected status 401, got: %v, body: %s", resp.StatusCode, respBody)
		}
	})

	t.Run("Failure: Missing session_id", func(t *testing.T) {
		// Create a client with mTLS configuration
		mtlsClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: certConfig,
			},
		}

		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/validate", baseURL), nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(middleware.APIKeyHeader, apiKey)
		// Missing Authorization header - this will be caught by the auth middleware

		resp, err := mtlsClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		respBody := logRequestAndResponse(t, req, resp, nil)

		// The server's auth middleware catches this before it gets to the session_id check
		// so we get a 401 Unauthorized instead of a 400 Bad Request
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected status 401 for missing session_id (auth middleware rejects first), got: %v, body: %s", resp.StatusCode, respBody)
		}
	})

	t.Run("Failure: Invalid session_id", func(t *testing.T) {
		// Create a client with mTLS configuration
		mtlsClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: certConfig,
			},
		}

		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/validate?session_id=invalid-session-id", baseURL), nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(middleware.APIKeyHeader, apiKey)

		resp, err := mtlsClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		respBody := logRequestAndResponse(t, req, resp, nil)

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected status 401 for invalid session_id, got: %v, body: %s", resp.StatusCode, respBody)
		}
	})
}
