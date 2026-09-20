package models

import (
	"strings"
	"time"

	"garde/pkg/config"
)

type LoginResponse struct {
	// SessionID is omitted unless the client opts in with X-Return-Session
	// (browser logins rely on the HttpOnly cookie only).
	SessionID string `json:"session_id,omitempty"`
}

type MFAResponse struct {
	Secret    string `json:"secret,omitempty"`
	QRCodeURL string `json:"qr_code_url,omitempty"`
}

type SuccessResponse struct {
	Data any `json:"data"`
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
	IsSuperuser    bool               `json:"is_superuser,omitempty"`
	IsAdmin        bool               `json:"is_admin,omitempty"`
}

func (u *UserResponse) IsUserAdmin() bool {
	if adminMap := config.GetAdminUsersMap(); len(adminMap) > 0 {
		if _, ok := adminMap[strings.ToLower(strings.TrimSpace(u.Email))]; ok {
			return true
		}
	}
	return false
}

type ListUsersResponse struct {
	Users []UserResponse `json:"users"`
	Total int            `json:"total,omitempty"`
	Page  int            `json:"page,omitempty"`
	Limit int            `json:"limit,omitempty"`
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

func NewSuccessResponse(data any) *SuccessResponse {
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
