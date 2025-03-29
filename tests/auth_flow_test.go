package integration

import (
	"garde/internal/models"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/joho/godotenv"
)

const (
	baseURL = "http://localhost:8443"
)

// Helper function to read and return response body
func readBody(resp *http.Response) string {
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(body)
}

// Helper function to log request and response, returns response body as string
func logRequestAndResponse(t *testing.T, req *http.Request, resp *http.Response, reqBody []byte) string {

	prettyPrintJSON := func(data []byte) string {
		var out bytes.Buffer
		if err := json.Indent(&out, data, "", "  "); err != nil {
			return string(data) // if JSON is invalid, just return raw data
		}
		return out.String()
	}

	t.Logf("\n\n========================================\n\nRequest:\nMethod: %s\nURL: %s\nHeaders: %v\nBody: %s\n",
		req.Method, req.URL, req.Header, prettyPrintJSON(reqBody))

	respBody := readBody(resp)
	t.Logf("\n\nResponse:\nStatus: %d\nHeaders: %v\nBody: %s\n",
		resp.StatusCode, resp.Header, prettyPrintJSON([]byte(respBody)))	

	// Create a new reader with the body content for further use
	resp.Body = io.NopCloser(bytes.NewBufferString(respBody))
	return respBody
}

func TestAuthenticationFlow(t *testing.T) {
	// Load .env file
	if err := godotenv.Load("../.env"); err != nil {
		t.Fatalf("Error loading .env file: %v", err)
	}

	// Wait for services to be ready
	time.Sleep(5 * time.Second)

	// Test data
	email := fmt.Sprintf("testuser_%d@example.com", time.Now().Unix())
	initialPassword := "Initial@123"
	changedPassword := "Changed@123"

	// 1. Create a new user
	createUserReq := models.CreateUserRequest{
		Email:    email,
		Password: initialPassword,
	}
	createUserBody, _ := json.Marshal(createUserReq)
	req, _ := http.NewRequest("POST", baseURL+"/users", bytes.NewBuffer(createUserBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	respBody := logRequestAndResponse(t, req, resp, createUserBody)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create user: %v, status: %v, body: %s", err, resp.StatusCode, respBody)
	}
	resp.Body.Close()

	// 2. Login with initial password
	loginReq := models.LoginRequest{
		Email:    email,
		Password: initialPassword,
	}
	loginBody, _ := json.Marshal(loginReq)
	req, _ = http.NewRequest("POST", baseURL+"/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	respBody = logRequestAndResponse(t, req, resp, loginBody)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to login: %v, status: %v, body: %s", err, resp.StatusCode, respBody)
	}

	var loginResp models.SuccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("Failed to decode login response: %v, body: %s", err, respBody)
	}
	loginData := loginResp.Data.(map[string]interface{})
	sessionID := loginData["session_id"].(string)
	resp.Body.Close()

	// 3. Get user information with /me endpoint
	req, _ = http.NewRequest("GET", baseURL+"/users/me", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sessionID))
	resp, err = http.DefaultClient.Do(req)
	respBody = logRequestAndResponse(t, req, resp, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to get user info: %v, status: %v, body: %s", err, resp.StatusCode, respBody)
	}
	resp.Body.Close()

	// 4. Change password
	changePassReq := models.ChangePasswordRequest{
		OldPassword: initialPassword,
		NewPassword: changedPassword,
	}
	changePassBody, _ := json.Marshal(changePassReq)
	req, _ = http.NewRequest("POST", baseURL+"/users/password/change", bytes.NewBuffer(changePassBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sessionID))
	resp, err = http.DefaultClient.Do(req)
	respBody = logRequestAndResponse(t, req, resp, changePassBody)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to change password: %v, status: %v, body: %s", err, resp.StatusCode, respBody)
	}
	resp.Body.Close()

	// 5. Try logging in with old password (should fail)
	loginReq.Password = initialPassword
	loginBody, _ = json.Marshal(loginReq)
	req, _ = http.NewRequest("POST", baseURL+"/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	respBody = logRequestAndResponse(t, req, resp, loginBody)
	if err != nil {
		t.Fatalf("Failed to make login request: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Login with old password should fail, got status: %v, body: %s", resp.StatusCode, respBody)
	}
	resp.Body.Close()

	// 6. Login with new password (should succeed)
	loginReq.Password = changedPassword
	loginBody, _ = json.Marshal(loginReq)
	req, _ = http.NewRequest("POST", baseURL+"/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	respBody = logRequestAndResponse(t, req, resp, loginBody)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to login with new password: %v, status: %v, body: %s", err, resp.StatusCode, respBody)
	}
	resp.Body.Close()

	// 7. Request password reset (this will send OTP to email)
	resetReq := models.RequestOTPRequest{Email: email}
	resetBody, _ := json.Marshal(resetReq)
	req, _ = http.NewRequest("POST", baseURL+"/users/password/otp", bytes.NewBuffer(resetBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	respBody = logRequestAndResponse(t, req, resp, resetBody)
	if err != nil {
		t.Fatalf("Failed to make password reset request: %v", err)
	}
	// In test environment, we expect a 400 with "failed to send mail" error
	// This is normal as the mail service is not configured in test environment
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected BadRequest status for mail service error, got: %v, body: %s", resp.StatusCode, respBody)
	}
	// Verify it's the expected mail error
	var errorResp models.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}
	if errorResp.Details.Message != "failed to send mail" {
		t.Fatalf("Expected 'failed to send mail' error, got: %s", errorResp.Details.Message)
	}
	resp.Body.Close()

	t.Log("Integration test completed successfully!")
}
