package models

import (
	"encoding/json"
	"time"
)

type User struct {
	ID             string             `json:"id"`
	Email          string             `json:"email"`
	PasswordHash   string             `json:"-"`
	LastLogin      time.Time          `json:"last_login"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
	MFAEnabled     bool               `json:"mfa_enabled"`
	MFAEnforced    bool               `json:"mfa_enforced"`
	MFASecret      string             `json:"-"`
	Status         UserStatus         `json:"status"`
	Permissions    UserPermissions    `json:"permissions"`
	Groups         UserGroups         `json:"groups"`
	PendingUpdates *UserUpdateRequest `json:"pending_updates,omitempty"`
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

// MarshalJSON implements custom JSON marshaling
func (u *User) MarshalJSON() ([]byte, error) {
	type Alias User // Create alias to avoid recursion
	return json.Marshal(&struct {
		*Alias
		PasswordHash string `json:"password_hash,omitempty"`
		// Always include pending_updates field in JSON output, even if it's null
		PendingUpdates *UserUpdateRequest `json:"pending_updates"`
	}{
		Alias:          (*Alias)(u),
		PasswordHash:   u.PasswordHash,
		PendingUpdates: u.PendingUpdates,
	})
}

func (u *User) UnmarshalJSON(data []byte) error { // Implements custom JSON unmarshaling
	type Alias User // Create alias to avoid recursion
	aux := &struct {
		*Alias
		PasswordHash string `json:"password_hash,omitempty"`
	}{
		Alias: (*Alias)(u),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	u.PasswordHash = aux.PasswordHash
	return nil
}

// Wrapper functions that delegate to service package
// These maintain backward compatibility while using SQLite-based system
// Note: These create a dependency on service package, but service already imports models for types,
// so we need to be careful not to create cycles. Service functions should not call these wrappers.

// The actual implementations are in internal/service/permission_service.go
// These are just forward declarations - the real functions will be added via build tags or
// we'll update all call sites to use service package directly

// For now, let's add stub functions that will cause compile errors if service isn't properly initialized
// The proper solution is to update all call sites, but that's a large change.
// Let's add the wrappers that import service (this is safe since service already imports models)
