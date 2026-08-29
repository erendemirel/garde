package models

import (
	"encoding/json"
	"time"
)

type User struct {
	ID             string             `json:"id"`
	Email          string             `json:"email"`
	PasswordHash   string             `json:"-"` // Stored in Redis key user_password:{id}, never in user JSON
	LastLogin      time.Time          `json:"last_login"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
	MFAEnabled     bool               `json:"mfa_enabled"`
	MFAEnforced    bool               `json:"mfa_enforced"`
	MFASecret      string             `json:"-"` // Stored encrypted in Redis key user_mfa:{id}
	Status         UserStatus         `json:"status"`
	Permissions    UserPermissions    `json:"permissions"`
	Groups         UserGroups         `json:"groups"`
	PendingUpdates *UserUpdateRequest `json:"pending_updates"`
}

type UserStatus string

const (
	UserStatusOk               UserStatus = "ok"
	UserStatusLockedByAdmin    UserStatus = "locked by admin"
	UserStatusLockedBySecurity UserStatus = "locked by security"
	UserStatusPendingApproval  UserStatus = "pending admin approval"
	UserStatusApprovalRejected UserStatus = "admin approval rejected"
)

// Permission represents a single permission
type Permission string

type PermissionInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type UserPermissions map[Permission]bool

func (u *User) HasPermission(permission Permission) bool {
	if enabled, exists := u.Permissions[permission]; exists {
		return enabled
	}
	return false
}

func IsValidUserStatus(status UserStatus) bool {
	switch status {
	case UserStatusOk, UserStatusLockedByAdmin, UserStatusLockedBySecurity,
		UserStatusPendingApproval, UserStatusApprovalRejected:
		return true
	}
	return false
}

type UserGroup string

type UserGroupInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type UserGroups map[UserGroup]bool

// Helper function to check if two users share any groups
func SharesAnyUserGroup(groups1, groups2 UserGroups) bool {
	for group, enabled1 := range groups1 {
		if enabled1 {
			if enabled2, exists := groups2[group]; exists && enabled2 {
				return true
			}
		}
	}
	return false
}

type UserUpdateRequest struct {
	RequestedAt time.Time        `json:"requested_at"`
	Fields      UserUpdateFields `json:"fields"`
}

type UserUpdateFields struct {
	PermissionsAdd    []Permission `json:"permissions_add,omitempty"`
	PermissionsRemove []Permission `json:"permissions_remove,omitempty"`
	GroupsAdd         []UserGroup  `json:"groups_add,omitempty"`
	GroupsRemove      []UserGroup  `json:"groups_remove,omitempty"`
}

// legacyUserCredentials extracts sensitive fields that may still exist in older
// Redis user JSON blobs (pre separate-key storage). Used only for one-time migration.
type legacyUserCredentials struct {
	PasswordHash string `json:"password_hash"`
	MFASecret    string `json:"mfa_secret"`
}

// ParseLegacyCredentials reads password_hash / mfa_secret from raw user JSON if present.
func ParseLegacyCredentials(data []byte) (passwordHash, mfaSecret string) {
	var legacy legacyUserCredentials
	if err := json.Unmarshal(data, &legacy); err != nil {
		return "", ""
	}
	return legacy.PasswordHash, legacy.MFASecret
}
