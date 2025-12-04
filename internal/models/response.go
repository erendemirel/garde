package models

import (
	"garde/pkg/config"
	"strings"
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

func (u *UserResponse) IsUserAdmin() bool {
	adminUsers := config.Get("ADMIN_USERS")
	if adminUsers == "" {
		return false
	}
	for _, email := range strings.Split(adminUsers, ",") {
		if strings.TrimSpace(email) == u.Email {
			return true
		}
	}
	return false
}

type ListUsersResponse struct {
	Users []UserResponse `json:"users"`
}

type PermissionResponse struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type GroupResponse struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
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
