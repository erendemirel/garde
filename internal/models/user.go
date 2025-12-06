package models

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
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
	Name        string `json:"name"`        // From JSON
	Description string `json:"description"` // From JSON
}

var (
	permissionsMutex       sync.RWMutex
	permissionDescriptions map[Permission]PermissionInfo
	permissionsLoaded      bool
)

func LoadPermissions() error {
	permissionsMutex.Lock()
	defer permissionsMutex.Unlock()

	// Read permissions file
	data, err := os.ReadFile(filepath.Join("configs", "permissions.json"))
	if err != nil {
		// If file doesn't exist or is empty, initialize with empty map
		permissionDescriptions = make(map[Permission]PermissionInfo)
		permissionsLoaded = false
		return nil
	}

	// Parse JSON directly into our map
	tempPerms := make(map[Permission]PermissionInfo)
	if err := json.Unmarshal(data, &tempPerms); err != nil {
		// If JSON is invalid or empty, initialize with empty map
		permissionDescriptions = make(map[Permission]PermissionInfo)
		permissionsLoaded = false
		return nil
	}

	permissionDescriptions = tempPerms
	permissionsLoaded = true
	return nil
}

func GetPermissionInfo(p Permission) PermissionInfo {
	permissionsMutex.RLock()
	defer permissionsMutex.RUnlock()

	if info, exists := permissionDescriptions[p]; exists {
		return info
	}
	return PermissionInfo{
		Name:        string(p),
		Description: "No description available",
	}
}

func DefaultPermissions() UserPermissions {
	permissionsMutex.RLock()
	defer permissionsMutex.RUnlock()

	perms := UserPermissions{}
	if permissionsLoaded {
		for p := range permissionDescriptions {
			perms[p] = false
		}
	}
	return perms
}

func GetAllPermissions() []Permission {
	permissionsMutex.RLock()
	defer permissionsMutex.RUnlock()

	perms := make([]Permission, 0, len(permissionDescriptions))
	for p := range permissionDescriptions {
		perms = append(perms, p)
	}
	return perms
}

func IsValidPermission(p Permission) bool {
	permissionsMutex.RLock()
	defer permissionsMutex.RUnlock()

	_, exists := permissionDescriptions[p]
	return exists
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

func AdminPermissions() UserPermissions {
	permissionsMutex.RLock()
	defer permissionsMutex.RUnlock()

	perms := UserPermissions{}
	if permissionsLoaded {
		for p := range permissionDescriptions {
			perms[p] = true
		}
	}
	return perms
}

type UserGroup string

type UserGroupInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type UserGroups map[UserGroup]bool

var (
	groupsMutex       sync.RWMutex
	groupDescriptions map[UserGroup]UserGroupInfo
	groupsLoaded      bool
)

func LoadGroups() error {
	groupsMutex.Lock()
	defer groupsMutex.Unlock()

	data, err := os.ReadFile(filepath.Join("configs", "groups.json"))
	if err != nil {
		// If file doesn't exist or is empty, initialize with empty map
		groupDescriptions = make(map[UserGroup]UserGroupInfo)
		groupsLoaded = false
		return nil
	}

	tempGroups := make(map[UserGroup]UserGroupInfo)
	if err := json.Unmarshal(data, &tempGroups); err != nil {
		// If JSON is invalid or empty, initialize with empty map
		groupDescriptions = make(map[UserGroup]UserGroupInfo)
		groupsLoaded = false
		return nil
	}

	groupDescriptions = tempGroups
	groupsLoaded = true
	return nil
}

func GetGroupInfo(g UserGroup) UserGroupInfo {
	groupsMutex.RLock()
	defer groupsMutex.RUnlock()

	if !groupsLoaded {
		return UserGroupInfo{
			Name:        string(g),
			Description: "Groups system not loaded",
		}
	}

	if info, exists := groupDescriptions[g]; exists {
		return info
	}
	return UserGroupInfo{
		Name:        string(g),
		Description: "No description available",
	}
}

func GetAllUserGroups() []UserGroup {
	groupsMutex.RLock()
	defer groupsMutex.RUnlock()

	groups := make([]UserGroup, 0, len(groupDescriptions))
	for g := range groupDescriptions {
		groups = append(groups, g)
	}
	return groups
}

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

func IsValidUserGroup(group UserGroup) bool {
	groupsMutex.RLock()
	defer groupsMutex.RUnlock()

	if !groupsLoaded {
		return false
	}

	_, exists := groupDescriptions[group]
	return exists
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

func IsPermissionsLoaded() bool {
	permissionsMutex.RLock()
	defer permissionsMutex.RUnlock()
	return permissionsLoaded
}

func IsGroupsLoaded() bool {
	groupsMutex.RLock()
	defer groupsMutex.RUnlock()
	return groupsLoaded
}
