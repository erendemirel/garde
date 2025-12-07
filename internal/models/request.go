package models

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	MFACode  string `json:"mfa_code,omitempty"`
}

type MFASetupRequest struct {
	Email string `json:"email,omitempty"` // Required only for unauthenticated requests
}

type MFAVerifyRequest struct {
	Email string `json:"email,omitempty"` // Required only for unauthenticated requests
	Code  string `json:"code" binding:"required,len=6,numeric"`
}

type RevokeSessionRequest struct {
	UserID  string `json:"user_id" binding:"required"`
	MFACode string `json:"mfa_code,omitempty"`
}

type CreateUserRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type UpdateUserRequest struct {
	Status        *UserStatus          `json:"status,omitempty"`
	MFAEnforced   *bool                `json:"mfa_enforced,omitempty"`
	Permissions   *map[Permission]bool `json:"permissions,omitempty"`
	Groups        *map[UserGroup]bool  `json:"groups,omitempty"`
	ApproveUpdate bool                 `json:"approve_update,omitempty"`
	RejectUpdate  bool                 `json:"reject_update,omitempty"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required,min=8"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
	MFACode     string `json:"mfa_code,omitempty"`
}

type DisableMFARequest struct {
	MFACode string `json:"mfa_code" binding:"required,len=6,numeric"`
}

type RequestOTPRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type PasswordResetRequest struct {
	Email       string `json:"email" binding:"required,email"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
	OTP         string `json:"otp" binding:"required,len=5"`
	MFACode     string `json:"mfa_code,omitempty"`
}

// RequestUpdateFields is specifically for permission update requests
type RequestUpdateFields struct {
	PermissionsAdd    []string `json:"permissions_add,omitempty"`
	PermissionsRemove []string `json:"permissions_remove,omitempty"`
	GroupsAdd         []string `json:"groups_add,omitempty"`
	GroupsRemove      []string `json:"groups_remove,omitempty"`
}

type RequestUpdateRequest struct {
	Updates RequestUpdateFields `json:"updates" binding:"required"`
}

type UpdateRequestResponse struct {
	Message string `json:"message"`
}

// Permission management requests (superuser only)
type CreatePermissionRequest struct {
	Name       string `json:"name" binding:"required"`
	Definition string `json:"definition" binding:"required"`
}

type UpdatePermissionRequest struct {
	Definition string `json:"definition" binding:"required"`
}

// Group management requests (superuser only)
type CreateGroupRequest struct {
	Name       string `json:"name" binding:"required"`
	Definition string `json:"definition" binding:"required"`
}

type UpdateGroupRequest struct {
	Definition string `json:"definition" binding:"required"`
}

// Permission visibility management requests (superuser only)
type AddPermissionVisibilityRequest struct {
	PermissionName string `json:"permission_name" binding:"required"`
	GroupName      string `json:"group_name" binding:"required"`
}

type RemovePermissionVisibilityRequest struct {
	PermissionName string `json:"permission_name" binding:"required"`
	GroupName      string `json:"group_name" binding:"required"`
}
