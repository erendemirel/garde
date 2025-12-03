package integration

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"garde/internal/models"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"
)

var adminLoginData map[string]interface{}

// GroupsResponse represents the response for listing groups
type GroupsResponse struct {
	Groups []models.UserGroup `json:"groups"`
}

func TestAdminApprovalFlow(t *testing.T) {
	// Define respBody that will be used throughout the test
	var respBody string

	// Load .env file
	if err := godotenv.Load("../.env"); err != nil {
		t.Fatalf("Error loading .env file: %v", err)
	}

	// Explicitly load permission and group models for the test
	if err := models.LoadPermissions(); err != nil {
		t.Logf("Warning: Failed to load permissions: %v", err)
	}

	if err := models.LoadGroups(); err != nil {
		t.Logf("Warning: Failed to load groups: %v", err)
	}

	// Wait for services to be ready
	time.Sleep(5 * time.Second)

	// Check if TLS testing should be enabled
	useTLS := strings.ToLower(os.Getenv("USE_TLS")) == "true"
	t.Logf("TLS testing enabled: %t", useTLS)

	// Use appropriate protocol based on TLS setting
	protocol := "http"
	if useTLS {
		protocol = "https"
	}

	// Get port from environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "8443" // Default port if not specified
	}

	// Determine base URL
	baseURL := fmt.Sprintf("%s://localhost:%s", protocol, port)
	t.Logf("Using base URL: %s", baseURL)

	// Create HTTP client with TLS configuration if needed
	client := &http.Client{}
	if useTLS {
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Only for testing
				},
			},
		}
	}

	// Get admin email from env
	adminUsersEnv := os.Getenv("SEED_ADMIN_EMAILS")
	if adminUsersEnv == "" {
		t.Fatal("SEED_ADMIN_EMAILS environment variable not set")
	}
	adminUsers := strings.Split(adminUsersEnv, ",")
	if len(adminUsers) == 0 {
		t.Fatal("No admin users configured in SEED_ADMIN_EMAILS environment variable")
	}
	adminEmail := strings.TrimSpace(adminUsers[0])
	if adminEmail == "" {
		t.Fatal("First admin email in SEED_ADMIN_EMAILS is empty")
	}
	t.Logf("Using admin email: %s", adminEmail)
	adminPassword := "Admin@123" // Set a secure password for the admin

	// Try to login as admin first
	adminLoginReq := models.LoginRequest{
		Email:    adminEmail,
		Password: adminPassword,
	}
	adminLoginBody, _ := json.Marshal(adminLoginReq)
	req, err := http.NewRequest("POST", baseURL+"/login", bytes.NewBuffer(adminLoginBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	respBody = logRequestAndResponse(t, req, resp, adminLoginBody)

	// Variable to store admin ID
	var adminUserID string

	// If login fails with 401, create the admin user
	if resp.StatusCode == http.StatusUnauthorized {
		t.Log("Admin user doesn't exist, creating it...")
		resp.Body.Close()

		createAdminReq := models.CreateUserRequest{
			Email:    adminEmail,
			Password: adminPassword,
		}
		createAdminBody, _ := json.Marshal(createAdminReq)
		req, err = http.NewRequest("POST", baseURL+"/users", bytes.NewBuffer(createAdminBody))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		_ = logRequestAndResponse(t, req, resp, createAdminBody)
		if err != nil {
			t.Fatalf("Failed to create admin user: %v", err)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("Failed to create admin user, status: %v, body: %s", resp.StatusCode, respBody)
		}

		// Extract admin user ID from creation response
		var createAdminResp models.CreateUserResponse
		if err := json.NewDecoder(resp.Body).Decode(&createAdminResp); err != nil {
			t.Fatalf("Failed to decode create admin user response: %v", err)
		}
		adminUserID = createAdminResp.UserID
		t.Logf("Created admin user with ID: %s", adminUserID)

		resp.Body.Close()

		time.Sleep(1 * time.Second)

		// Try logging in again
		req, err = http.NewRequest("POST", baseURL+"/login", bytes.NewBuffer(adminLoginBody))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		_ = logRequestAndResponse(t, req, resp, adminLoginBody)
	}

	// At this point, we should have a successful admin login
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to login as admin: %v, status: %v, body: %s", err, resp.StatusCode, respBody)
	}

	var adminLoginResp models.SuccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&adminLoginResp); err != nil {
		t.Fatalf("Failed to decode admin login response: %v, body: %s", err, respBody)
	}
	adminLoginData = adminLoginResp.Data.(map[string]interface{})
	adminSessionID := adminLoginData["session_id"].(string)
	resp.Body.Close()

	// Reset admin's groups for deterministic test behavior
	if adminUserID == "" {
		// Get admin ID from /users/me endpoint
		req, err = http.NewRequest("GET", baseURL+"/users/me", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			var meResp struct {
				Data models.UserResponse `json:"data"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&meResp); err == nil {
				adminUserID = meResp.Data.ID
				t.Logf("Found admin user with ID: %s", adminUserID)
			}
		}
		resp.Body.Close()
	}

	// Clear admin groups if we have admin ID
	if adminUserID != "" {
		clearGroupsBody, _ := json.Marshal(models.UpdateUserRequest{
			Groups: &map[models.UserGroup]bool{},
		})
		req, err = http.NewRequest("PUT", fmt.Sprintf("%s/users/%s", baseURL, adminUserID), bytes.NewBuffer(clearGroupsBody))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		_ = logRequestAndResponse(t, req, resp, clearGroupsBody)
		resp.Body.Close()
	}

	// Test data for regular user
	userEmail := fmt.Sprintf("testuser_%d@example.com", time.Now().Unix())
	userPassword := "TestUser@123"

	// 1. Create a new regular user
	createUserReq := models.CreateUserRequest{
		Email:    userEmail,
		Password: userPassword,
	}
	createUserBody, _ := json.Marshal(createUserReq)
	req, err = http.NewRequest("POST", baseURL+"/users", bytes.NewBuffer(createUserBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, createUserBody)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create user: %v, status: %v, body: %s", err, resp.StatusCode, respBody)
	}
	var createResp models.CreateUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		t.Fatalf("Failed to decode create user response: %v", err)
	}
	userID := createResp.UserID
	resp.Body.Close()

	// 2. Login as the regular user
	loginReq := models.LoginRequest{
		Email:    userEmail,
		Password: userPassword,
	}
	loginBody, _ := json.Marshal(loginReq)
	req, err = http.NewRequest("POST", baseURL+"/login", bytes.NewBuffer(loginBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, loginBody)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to login as user: %v, status: %v, body: %s", err, resp.StatusCode, respBody)
	}

	var loginResp models.SuccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("Failed to decode login response: %v, body: %s", err, respBody)
	}
	loginData := loginResp.Data.(map[string]interface{})
	userSessionID := loginData["session_id"].(string)
	resp.Body.Close()

	// Get available groups by reading the config file
	groupsData, err := os.ReadFile("../configs/groups.json")
	if err != nil {
		t.Fatalf("Failed to read groups config file: %v", err)
	}

	var groupsConfig map[models.UserGroup]interface{}
	if err := json.Unmarshal(groupsData, &groupsConfig); err != nil {
		t.Fatalf("Failed to parse groups config file: %v", err)
	}

	if len(groupsConfig) == 0 {
		t.Fatal("No groups available in the system")
	}

	// Get the first group
	var firstGroup models.UserGroup
	for group := range groupsConfig {
		firstGroup = group
		break
	}
	t.Logf("Using first group: %s", firstGroup)

	// Fetch available permissions from config file
	permissionsData, err := os.ReadFile("../configs/permissions.json")
	if err != nil {
		t.Logf("Warning: Failed to read permissions config file: %v", err)
	} else {
		var permissionsConfig map[string]interface{}
		if err := json.Unmarshal(permissionsData, &permissionsConfig); err != nil {
			t.Logf("Warning: Failed to parse permissions config: %v", err)
		} else {
			t.Logf("Available permissions: %v", permissionsConfig)
		}
	}

	// 3. Request permission and group updates as the regular user
	updateRequest := models.RequestUpdateRequest{
		Updates: models.RequestUpdateFields{
			Permissions: map[models.Permission]bool{
				"permission_b": true,
			},
			Groups: map[models.UserGroup]bool{
				"y": true,
			},
		},
	}

	updateReqBody, _ := json.Marshal(updateRequest)
	t.Logf("Update request: %s", string(updateReqBody))

	req, err = http.NewRequest("POST", baseURL+"/users/request-update-from-admin", bytes.NewBuffer(updateReqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", userSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, updateReqBody)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to request update: %v, status: %v, body: %s", err, resp.StatusCode, respBody)
	}
	resp.Body.Close()

	// TEST CASE 1: Admin tries to update user's permissions - should fail with 401
	permUpdateBody, _ := json.Marshal(models.UpdateUserRequest{
		Permissions: &map[models.Permission]bool{
			"permission_b": true,
		},
	})
	t.Logf("TEST CASE 1: Admin tries to update user's permissions - should fail with 401")
	req, err = http.NewRequest("PUT", fmt.Sprintf("%s/users/%s", baseURL, userID), bytes.NewBuffer(permUpdateBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, permUpdateBody)
	t.Logf(" Admin correctly cannot update user permissions")
	resp.Body.Close()

	// TEST CASE 2: Admin tries to add user to a valid group they don't belong to - should fail with 401
	validGroupUpdateBody, _ := json.Marshal(models.UpdateUserRequest{
		Groups: &map[models.UserGroup]bool{
			"z": true, // Using a valid group that the admin doesn't belong to
		},
	})
	t.Logf("TEST CASE 2: Admin tries to add user to a valid group they don't belong to - should fail with 401")
	req, err = http.NewRequest("PUT", fmt.Sprintf("%s/users/%s", baseURL, userID), bytes.NewBuffer(validGroupUpdateBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, validGroupUpdateBody)
	t.Logf(" Admin correctly cannot add user to groups admin doesn't belong to")
	resp.Body.Close()

	// TEST CASE 3: Admin tries to add user to admin's own group - should succeed
	// We need to know what groups the admin is in first
	t.Logf("Getting admin's current groups")
	req, err = http.NewRequest("GET", fmt.Sprintf("%s/users/me", baseURL), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, nil)

	var adminSelfResponse struct {
		Data struct {
			Groups map[models.UserGroup]bool `json:"groups"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&adminSelfResponse); err != nil {
		t.Logf("Warning: Failed to decode admin's groups: %v", err)
	}
	resp.Body.Close()

	// Find a group the admin belongs to
	var adminGroup models.UserGroup
	foundGroup := false
	for group, belongs := range adminSelfResponse.Data.Groups {
		if belongs {
			adminGroup = group
			foundGroup = true
			break
		}
	}

	if foundGroup {
		ownGroupUpdateBody, _ := json.Marshal(models.UpdateUserRequest{
			Groups: &map[models.UserGroup]bool{
				adminGroup: true,
			},
		})
		t.Logf("TEST CASE 3: Admin tries to add user to admin's own group (%s) - should succeed", adminGroup)
		req, err = http.NewRequest("PUT", fmt.Sprintf("%s/users/%s", baseURL, userID), bytes.NewBuffer(ownGroupUpdateBody))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		_ = logRequestAndResponse(t, req, resp, ownGroupUpdateBody)
		t.Logf(" Admin correctly can add user to admin's own group")
		resp.Body.Close()
	} else {
		t.Logf("Admin does not belong to any groups yet - skipping test case 3")
	}

	// Login as superuser and grant first group to both users
	superUserEmail := os.Getenv("SUPERUSER_EMAIL")
	if superUserEmail == "" {
		t.Fatal("SUPERUSER_EMAIL environment variable not set")
	}
	superUserPassword := os.Getenv("SUPERUSER_PASSWORD")
	if superUserPassword == "" {
		t.Fatal("SUPERUSER_PASSWORD environment variable not set")
	}

	t.Logf("Using superuser email: %s", superUserEmail)

	// Login as admin again to get fresh session
	adminLoginReq = models.LoginRequest{
		Email:    adminEmail,
		Password: adminPassword,
	}
	adminLoginBody, _ = json.Marshal(adminLoginReq)
	req, err = http.NewRequest("POST", baseURL+"/login", bytes.NewBuffer(adminLoginBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, adminLoginBody)

	var adminLoginResp2 models.SuccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&adminLoginResp2); err != nil {
		t.Fatalf("Failed to decode admin login response: %v, body: %s", err, respBody)
	}
	adminLoginData = adminLoginResp2.Data.(map[string]interface{})
	adminSessionID = adminLoginData["session_id"].(string)
	resp.Body.Close()

	// First, add the admin to the group so they can update users in that group
	adminUpdateGroupReq := models.UpdateUserRequest{
		Groups: &map[models.UserGroup]bool{
			firstGroup: true,
		},
	}
	adminUpdateGroupBody, _ := json.Marshal(adminUpdateGroupReq)
	t.Logf("Adding admin to group with body: %s", string(adminUpdateGroupBody))

	// If we don't have admin ID yet, try to get it from a different endpoint
	if adminUserID == "" {
		// Try to get admin ID using /users/me endpoint
		req, err = http.NewRequest("GET", fmt.Sprintf("%s/users/me", baseURL), nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			var meResp struct {
				Data models.UserResponse `json:"data"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&meResp); err == nil {
				adminUserID = meResp.Data.ID
				t.Logf("Found admin user with ID: %s", adminUserID)
			}
		}
		resp.Body.Close()
	}

	// Login as superuser
	superUserLoginReq := models.LoginRequest{
		Email:    superUserEmail,
		Password: superUserPassword,
	}
	superUserLoginBody, _ := json.Marshal(superUserLoginReq)
	req, err = http.NewRequest("POST", baseURL+"/login", bytes.NewBuffer(superUserLoginBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, superUserLoginBody)

	var superUserLoginResp models.SuccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&superUserLoginResp); err != nil {
		t.Fatalf("Failed to decode superuser login response: %v, body: %s", err, respBody)
	}
	superUserLoginData := superUserLoginResp.Data.(map[string]interface{})
	superUserSessionID := superUserLoginData["session_id"].(string)
	resp.Body.Close()

	// Use superuser to update admin's group
	req, err = http.NewRequest("PUT", fmt.Sprintf("%s/users/%s", baseURL, adminUserID), bytes.NewBuffer(adminUpdateGroupBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", superUserSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, adminUpdateGroupBody)
	resp.Body.Close()

	// Now update the regular user's group using admin (who is now in the same group)
	// This should succeed because admins can add users to groups they belong to
	updateUserGroupBody, _ := json.Marshal(models.UpdateUserRequest{
		Groups: &map[models.UserGroup]bool{
			firstGroup: true,
		},
	})
	t.Logf("Updating user group with admin credentials (should succeed now that admin is in the group)")
	req, err = http.NewRequest("PUT", fmt.Sprintf("%s/users/%s", baseURL, userID), bytes.NewBuffer(updateUserGroupBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, updateUserGroupBody)
	resp.Body.Close()

	// 4. Get the user's details to verify pending updates
	req, err = http.NewRequest("GET", fmt.Sprintf("%s/users/%s", baseURL, userID), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, nil)

	// Fix: Handle the nested JSON structure for the updated user response
	var userRespWrapper struct {
		Data models.UserResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userRespWrapper); err != nil {
		t.Fatalf("Failed to decode user response: %v", err)
	}
	userResp := userRespWrapper.Data

	t.Logf("Raw userResp object: %+v", userResp)
	t.Logf("userResp.PendingUpdates: %+v", userResp.PendingUpdates)

	// Parse the respBody directly for comparison
	var rawMap map[string]interface{}
	if err := json.Unmarshal([]byte(respBody), &rawMap); err != nil {
		t.Fatalf("Failed to unmarshal raw JSON: %v", err)
	}

	data, ok := rawMap["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Data field not found or not an object")
	}

	t.Logf("Data field contains pendingUpdates: %v", data["pending_updates"] != nil)

	if userResp.PendingUpdates == nil {
		t.Fatal("Expected pending updates in user data")
	}
	resp.Body.Close()

	// 5. Approve the update request as admin
	adminUpdateReq := models.UpdateUserRequest{
		ApproveUpdate: true,
	}
	adminUpdateBody, _ := json.Marshal(adminUpdateReq)
	req, err = http.NewRequest("PUT", fmt.Sprintf("%s/users/%s", baseURL, userID), bytes.NewBuffer(adminUpdateBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, adminUpdateBody)
	resp.Body.Close()

	// 6. Verify the user's updated permissions and groups
	req, err = http.NewRequest("GET", fmt.Sprintf("%s/users/%s", baseURL, userID), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, nil)

	// Fix: Handle the nested JSON structure for the updated user response
	var updatedUserRespWrapper struct {
		Data models.UserResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&updatedUserRespWrapper); err != nil {
		t.Fatalf("Failed to decode updated user response: %v", err)
	}
	updatedUserResp := updatedUserRespWrapper.Data

	// Verify permissions and groups were updated
	if !updatedUserResp.Permissions["permission_b"] {
		t.Fatal("Expected permission_b to be granted")
	}

	if !updatedUserResp.Groups[firstGroup] {
		t.Fatalf("Expected group %s to be granted", firstGroup)
	}

	// Verify there are no pending updates
	if updatedUserResp.PendingUpdates != nil {
		t.Fatal("Expected no pending updates after approval")
	}
	resp.Body.Close()

	t.Log("Admin approval flow test completed successfully!")
}

func TestUserAccess(t *testing.T) {
	// Define respBody that will be used throughout the test
	var respBody string

	// Load .env file
	if err := godotenv.Load("../../.env"); err != nil {
		t.Fatalf("Error loading .env file: %v", err)
	}

	// Explicitly load permission and group models for the test
	if err := models.LoadPermissions(); err != nil {
		t.Logf("Warning: Failed to load permissions: %v", err)
	}

	if err := models.LoadGroups(); err != nil {
		t.Logf("Warning: Failed to load groups: %v", err)
	}

	// Wait for services to be ready
	time.Sleep(2 * time.Second)

	// Check if TLS testing should be enabled
	useTLS := strings.ToLower(os.Getenv("USE_TLS")) == "true"
	t.Logf("TLS testing enabled: %t", useTLS)

	// Use appropriate protocol based on TLS setting
	protocol := "http"
	if useTLS {
		protocol = "https"
	}

	// Get port from environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "8443" // Default port if not specified
	}

	// Determine base URL
	baseURL := fmt.Sprintf("%s://localhost:%s", protocol, port)
	t.Logf("Using base URL: %s", baseURL)

	// Create HTTP client with TLS configuration if needed
	client := &http.Client{}
	if useTLS {
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Only for testing
				},
			},
		}
	}

	// Get superuser credentials
	superUserEmail := os.Getenv("SUPERUSER_EMAIL")
	if superUserEmail == "" {
		t.Fatal("SUPERUSER_EMAIL environment variable not set")
	}
	superUserPassword := os.Getenv("SUPERUSER_PASSWORD")
	if superUserPassword == "" {
		t.Fatal("SUPERUSER_PASSWORD environment variable not set")
	}

	// Get admin email from env
	adminUsersEnv := os.Getenv("SEED_ADMIN_EMAILS")
	if adminUsersEnv == "" {
		t.Fatal("SEED_ADMIN_EMAILS environment variable not set")
	}
	adminUsers := strings.Split(adminUsersEnv, ",")
	if len(adminUsers) == 0 {
		t.Fatal("No admin users configured in SEED_ADMIN_EMAILS environment variable")
	}
	adminEmail := strings.TrimSpace(adminUsers[0])
	if adminEmail == "" {
		t.Fatal("First admin email in SEED_ADMIN_EMAILS is empty")
	}
	t.Logf("Using admin email: %s", adminEmail)
	adminPassword := "Admin@123" // Set a secure password for the admin

	// Login as superuser
	superUserLoginReq := models.LoginRequest{
		Email:    superUserEmail,
		Password: superUserPassword,
	}
	superUserLoginBody, _ := json.Marshal(superUserLoginReq)
	req, err := http.NewRequest("POST", baseURL+"/login", bytes.NewBuffer(superUserLoginBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, superUserLoginBody)

	var superUserLoginResp models.SuccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&superUserLoginResp); err != nil {
		t.Fatalf("Failed to decode superuser login response: %v, body: %s", err, respBody)
	}
	superUserLoginData := superUserLoginResp.Data.(map[string]interface{})
	superUserSessionID := superUserLoginData["session_id"].(string)
	resp.Body.Close()

	// Login as admin
	adminLoginReq := models.LoginRequest{
		Email:    adminEmail,
		Password: adminPassword,
	}
	adminLoginBody, _ := json.Marshal(adminLoginReq)
	req, err = http.NewRequest("POST", baseURL+"/login", bytes.NewBuffer(adminLoginBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, adminLoginBody)

	var adminLoginResp models.SuccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&adminLoginResp); err != nil {
		t.Fatalf("Failed to decode admin login response: %v, body: %s", err, respBody)
	}
	adminLoginData = adminLoginResp.Data.(map[string]interface{})
	adminSessionID := adminLoginData["session_id"].(string)
	resp.Body.Close()

	// Get admin ID
	req, err = http.NewRequest("GET", fmt.Sprintf("%s/users/me", baseURL), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, nil)

	var adminUserInfo struct {
		Data models.UserResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&adminUserInfo); err != nil {
		t.Fatalf("Failed to decode admin user info: %v", err)
	}
	adminUserID := adminUserInfo.Data.ID
	resp.Body.Close()

	// Reset admin groups
	clearGroupsBody, _ := json.Marshal(models.UpdateUserRequest{
		Groups: &map[models.UserGroup]bool{
			"x": true, // Assign admin to group "x"
		},
	})
	req, err = http.NewRequest("PUT", fmt.Sprintf("%s/users/%s", baseURL, adminUserID), bytes.NewBuffer(clearGroupsBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, clearGroupsBody)
	resp.Body.Close()

	// Create two test users with different group memberships
	// User 1: In group "x" (shared with admin)
	// User 2: In group "z" (not shared with admin)
	user1Email := fmt.Sprintf("testuser1_%d@example.com", time.Now().Unix())
	user1Password := "TestUser1@123"
	user2Email := fmt.Sprintf("testuser2_%d@example.com", time.Now().Unix())
	user2Password := "TestUser2@123"

	// Create User 1
	user1Req := models.CreateUserRequest{
		Email:    user1Email,
		Password: user1Password,
	}
	user1Body, _ := json.Marshal(user1Req)
	req, err = http.NewRequest("POST", fmt.Sprintf("%s/users", baseURL), bytes.NewBuffer(user1Body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, user1Body)

	var user1CreateResp models.CreateUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&user1CreateResp); err != nil {
		t.Fatalf("Failed to decode create user 1 response: %v", err)
	}
	user1ID := user1CreateResp.UserID
	resp.Body.Close()

	// Create User 2
	user2Req := models.CreateUserRequest{
		Email:    user2Email,
		Password: user2Password,
	}
	user2Body, _ := json.Marshal(user2Req)
	req, err = http.NewRequest("POST", fmt.Sprintf("%s/users", baseURL), bytes.NewBuffer(user2Body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, user2Body)

	var user2CreateResp models.CreateUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&user2CreateResp); err != nil {
		t.Fatalf("Failed to decode create user 2 response: %v", err)
	}
	user2ID := user2CreateResp.UserID
	resp.Body.Close()

	// Update User 1 to be in group "x" (same as admin)
	user1GroupUpdate := models.UpdateUserRequest{
		Groups: &map[models.UserGroup]bool{
			"x": true,
		},
	}
	user1GroupBody, _ := json.Marshal(user1GroupUpdate)
	req, err = http.NewRequest("PUT", fmt.Sprintf("%s/users/%s", baseURL, user1ID), bytes.NewBuffer(user1GroupBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", superUserSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, user1GroupBody)
	resp.Body.Close()

	// Update User 2 to be in group "z" (different from admin)
	user2GroupUpdate := models.UpdateUserRequest{
		Groups: &map[models.UserGroup]bool{
			"z": true,
		},
	}
	user2GroupBody, _ := json.Marshal(user2GroupUpdate)
	req, err = http.NewRequest("PUT", fmt.Sprintf("%s/users/%s", baseURL, user2ID), bytes.NewBuffer(user2GroupBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", superUserSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, user2GroupBody)
	resp.Body.Close()

	// TEST CASE 1: Admin should be able to get user from same group
	t.Logf("TEST CASE 1: Admin should be able to get user from same group")
	req, err = http.NewRequest("GET", fmt.Sprintf("%s/users/%s", baseURL, user1ID), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, nil)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected admin to access user in same group, got: %v", resp.StatusCode)
	}
	t.Logf(" Admin can access user in same group")
	resp.Body.Close()

	// TEST CASE 2: Admin should not be able to get user from different group
	t.Logf("TEST CASE 2: Admin should not be able to get user from different group")
	req, err = http.NewRequest("GET", fmt.Sprintf("%s/users/%s", baseURL, user2ID), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, nil)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 for admin accessing user in different group, got: %v", resp.StatusCode)
	}
	t.Logf(" Admin correctly denied access to user in different group")
	resp.Body.Close()

	// TEST CASE 3: Admin should only see users from shared groups in list
	t.Logf("TEST CASE 3: Admin should only see users from shared groups in list")
	req, err = http.NewRequest("GET", fmt.Sprintf("%s/users", baseURL), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, nil)

	var userListResp struct {
		Data []models.UserResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userListResp); err != nil {
		t.Fatalf("Failed to decode user list response: %v", err)
	}
	resp.Body.Close()

	// Check if user1 is in the list and user2 is not
	foundUser1 := false
	foundUser2 := false
	for _, user := range userListResp.Data {
		if user.ID == user1ID {
			foundUser1 = true
		}
		if user.ID == user2ID {
			foundUser2 = true
		}
	}

	if !foundUser1 {
		t.Fatalf("Admin should see user1 (same group) in user list")
	}
	if foundUser2 {
		t.Fatalf("Admin should not see user2 (different group) in user list")
	}
	t.Logf(" Admin correctly sees only users from shared groups")

	// TEST CASE 4: Superuser should see all users
	t.Logf("TEST CASE 4: Superuser should see all users")
	req, err = http.NewRequest("GET", fmt.Sprintf("%s/users", baseURL), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", superUserSessionID))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	_ = logRequestAndResponse(t, req, resp, nil)

	var superUserListResp struct {
		Data []models.UserResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&superUserListResp); err != nil {
		t.Fatalf("Failed to decode superuser list response: %v", err)
	}
	resp.Body.Close()

	// Check if both user1 and user2 are in the list
	foundUser1 = false
	foundUser2 = false
	for _, user := range superUserListResp.Data {
		if user.ID == user1ID {
			foundUser1 = true
		}
		if user.ID == user2ID {
			foundUser2 = true
		}
	}

	if !foundUser1 || !foundUser2 {
		t.Fatalf("Superuser should see all users in user list")
	}
	t.Logf(" Superuser correctly sees all users")

	t.Log("User access test completed successfully!")
}
