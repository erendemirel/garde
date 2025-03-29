package models

import (
	"encoding/json"
	"time"
)

type LoginResponse struct {
	SessionID string `json:"session_id"`
}

type MFAResponse struct {
	Secret    string `json:"secret,omitempty"`
	QRCodeURL string `json:"qr_code_url,omitempty"`
}

type SuccessResponse struct {
	Data interface{} `json:"data"`
}

type ErrorResponse struct {
	Details ErrorDetails `json:"error"`
}

type ErrorDetails struct {
	Message string `json:"message"`
}

type CreateUserResponse struct {
	UserID string `json:"user_id"`
}

type SessionValidationResponse struct {
	Valid bool `json:"valid"`
}

type UserResponse struct {
	ID             string             `json:"id"`
	Email          string             `json:"email"`
	LastLogin      time.Time          `json:"last_login"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
	MFAEnabled     bool               `json:"mfa_enabled"`
	MFAEnforced    bool               `json:"mfa_enforced"`
	Status         UserStatus         `json:"status"`
	Permissions    UserPermissions    `json:"permissions"`
	Groups         UserGroups         `json:"groups"`
	PendingUpdates *UserUpdateRequest `json:"pending_updates,omitempty"`
}

func (u *UserResponse) MarshalJSON() ([]byte, error) {  // Implements custom JSON marshaling for UserResponse
	type Alias UserResponse // Create alias to avoid recursion
	return json.Marshal(&struct {
		*Alias
		// Always include pending_updates field in JSON output, even if it's null
		PendingUpdates *UserUpdateRequest `json:"pending_updates"`
	}{
		Alias:          (*Alias)(u),
		PendingUpdates: u.PendingUpdates,
	})
}

type ListUsersResponse struct {
	Users []UserResponse `json:"users"`
}

func NewSuccessResponse(data interface{}) *SuccessResponse {
	return &SuccessResponse{
		Data: data,
	}
}

func NewErrorResponse(message string) *ErrorResponse {
	return &ErrorResponse{
		Details: ErrorDetails{
			Message: message,
		},
	}
}

func (e *ErrorResponse) Error() string {
	return e.Details.Message
}
