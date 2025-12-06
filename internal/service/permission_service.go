package service

import (
	"context"
	"garde/internal/models"
	"garde/internal/repository"
	"log/slog"
	"sync"
)

var (
	permRepo     *repository.PermissionRepository
	permRepoOnce sync.Once
	permRepoErr  error
)

// InitPermissionRepository initializes the permission repository
// This should be called once at application startup
func InitPermissionRepository() error {
	permRepoOnce.Do(func() {
		permRepo, permRepoErr = repository.GetPermissionRepository()
		if permRepoErr != nil {
			slog.Error("Failed to initialize permission repository", "error", permRepoErr)
		} else {
			slog.Info("Permission repository initialized successfully")
		}
	})
	return permRepoErr
}

// GetPermissionRepository returns the permission repository instance
func GetPermissionRepository() *repository.PermissionRepository {
	return permRepo
}

// IsPermissionsLoaded checks if permissions system is loaded
func IsPermissionsLoaded() bool {
	return permRepo != nil
}

// IsGroupsLoaded checks if groups system is loaded
func IsGroupsLoaded() bool {
	return permRepo != nil
}

// GetAllPermissions returns all permissions (for superuser/admin use)
func GetAllPermissions() []models.Permission {
	if permRepo == nil {
		return []models.Permission{}
	}

	ctx := context.Background()
	entities, err := permRepo.GetAllPermissions(ctx)
	if err != nil {
		slog.Error("Failed to get all permissions", "error", err)
		return []models.Permission{}
	}

	perms := make([]models.Permission, len(entities))
	for i, e := range entities {
		perms[i] = models.Permission(e.Name)
	}
	return perms
}

// GetVisiblePermissions returns permissions visible to the given groups
func GetVisiblePermissions(groupNames []string) []models.Permission {
	if permRepo == nil {
		return []models.Permission{}
	}

	if len(groupNames) == 0 {
		return []models.Permission{}
	}

	ctx := context.Background()
	entities, err := permRepo.GetVisiblePermissions(ctx, groupNames)
	if err != nil {
		slog.Error("Failed to get visible permissions", "error", err, "groups", groupNames)
		return []models.Permission{}
	}

	perms := make([]models.Permission, len(entities))
	for i, e := range entities {
		perms[i] = models.Permission(e.Name)
	}
	return perms
}

// GetAllUserGroups returns all groups
func GetAllUserGroups() []models.UserGroup {
	if permRepo == nil {
		return []models.UserGroup{}
	}

	ctx := context.Background()
	entities, err := permRepo.GetAllGroups(ctx)
	if err != nil {
		slog.Error("Failed to get all groups", "error", err)
		return []models.UserGroup{}
	}

	groups := make([]models.UserGroup, len(entities))
	for i, e := range entities {
		groups[i] = models.UserGroup(e.Name)
	}
	return groups
}

// GetPermissionInfo returns permission info by name
func GetPermissionInfo(p models.Permission) models.PermissionInfo {
	if permRepo == nil {
		return models.PermissionInfo{
			Name:        string(p),
			Description: "No description available",
		}
	}

	ctx := context.Background()
	entity, err := permRepo.GetPermissionByName(ctx, string(p))
	if err != nil {
		return models.PermissionInfo{
			Name:        string(p),
			Description: "No description available",
		}
	}

	return models.PermissionInfo{
		Name:        entity.Name,
		Description: entity.Definition,
	}
}

// GetGroupInfo returns group info by name
func GetGroupInfo(g models.UserGroup) models.UserGroupInfo {
	if permRepo == nil {
		return models.UserGroupInfo{
			Name:        string(g),
			Description: "No description available",
		}
	}

	ctx := context.Background()
	entity, err := permRepo.GetGroupByName(ctx, string(g))
	if err != nil {
		return models.UserGroupInfo{
			Name:        string(g),
			Description: "No description available",
		}
	}

	return models.UserGroupInfo{
		Name:        entity.Name,
		Description: entity.Definition,
	}
}

// IsValidPermission checks if a permission exists
func IsValidPermission(p models.Permission) bool {
	if permRepo == nil {
		return false
	}

	ctx := context.Background()
	_, err := permRepo.GetPermissionByName(ctx, string(p))
	return err == nil
}

// IsValidUserGroup checks if a group exists
func IsValidUserGroup(group models.UserGroup) bool {
	if permRepo == nil {
		return false
	}

	ctx := context.Background()
	_, err := permRepo.GetGroupByName(ctx, string(group))
	return err == nil
}

// IsPermissionVisibleToGroups checks if a permission is visible to any of the given groups
func IsPermissionVisibleToGroups(permissionName string, groupNames []string) bool {
	if permRepo == nil || len(groupNames) == 0 {
		return false
	}

	ctx := context.Background()
	visible, err := permRepo.IsPermissionVisibleToGroups(ctx, permissionName, groupNames)
	if err != nil {
		slog.Error("Failed to check permission visibility", "error", err, "permission", permissionName, "groups", groupNames)
		return false
	}
	return visible
}

// GetUserGroupNames extracts group names from UserGroups map
func GetUserGroupNames(groups models.UserGroups) []string {
	var names []string
	for group, enabled := range groups {
		if enabled {
			names = append(names, string(group))
		}
	}
	return names
}

// DefaultPermissions returns default permissions map (all false)
func DefaultPermissions() models.UserPermissions {
	perms := models.UserPermissions{}
	allPerms := GetAllPermissions()
	for _, p := range allPerms {
		perms[p] = false
	}
	return perms
}

// AdminPermissions returns admin permissions map (all true)
func AdminPermissions() models.UserPermissions {
	perms := models.UserPermissions{}
	allPerms := GetAllPermissions()
	for _, p := range allPerms {
		perms[p] = true
	}
	return perms
}
