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
	Permissions map[Permission]bool `json:"permissions,omitempty"`
	Groups      map[UserGroup]bool  `json:"groups,omitempty"`
}

type RequestUpdateRequest struct {
	Updates RequestUpdateFields `json:"updates" binding:"required"`
}

type UpdateRequestResponse struct {
	Message string `json:"message"`
}
