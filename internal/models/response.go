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

// Checks if user belongs to the internal admin group
func (u *UserResponse) IsUserAdmin() bool {
	if u.Groups == nil {
		return false
	}
	return u.Groups[InternalAdminGroup]
}

func (u *UserResponse) MarshalJSON() ([]byte, error) {
	// Filter out internal __admin__ group from response
	filteredGroups := make(UserGroups)
	for group, enabled := range u.Groups {
		if group != InternalAdminGroup {
			filteredGroups[group] = enabled
		}
	}

	type Alias UserResponse // Create alias to avoid recursion
	return json.Marshal(&struct {
		*Alias
		Groups         UserGroups         `json:"groups"`
		PendingUpdates *UserUpdateRequest `json:"pending_updates"`
	}{
		Alias:          (*Alias)(u),
		Groups:         filteredGroups,
		PendingUpdates: u.PendingUpdates,
	})
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
