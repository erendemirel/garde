package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"garde/internal/entities"
)

// PermissionRepository is the catalogue of permissions, groups, and which
// groups may see which permission. It shares the Store's PostgreSQL pool: the
// catalogue is read on nearly every authorization decision, so it belongs
// beside the accounts it describes rather than in a second database.
type PermissionRepository struct {
	db *sql.DB
	mu sync.RWMutex
}

var (
	permissionRepo   *PermissionRepository
	permissionRepoMu sync.RWMutex
)

// NewPermissionRepository wraps an already-open pool. The schema is owned by
// Migrate, so there is nothing to create here.
func NewPermissionRepository(db *sql.DB) (*PermissionRepository, error) {
	if db == nil {
		return nil, errPostgresUnavailable
	}
	return &PermissionRepository{db: db}, nil
}

// InitPermissionRepository installs the process-wide catalogue. Call it once,
// at startup, with the pool the Store opened.
func InitPermissionRepository(db *sql.DB) (*PermissionRepository, error) {
	repo, err := NewPermissionRepository(db)
	if err != nil {
		return nil, err
	}

	permissionRepoMu.Lock()
	defer permissionRepoMu.Unlock()
	permissionRepo = repo
	return repo, nil
}

// GetPermissionRepository returns the catalogue installed at startup.
func GetPermissionRepository() (*PermissionRepository, error) {
	permissionRepoMu.RLock()
	defer permissionRepoMu.RUnlock()
	if permissionRepo == nil {
		return nil, fmt.Errorf("permission repository is not initialized")
	}
	return permissionRepo, nil
}

func (r *PermissionRepository) GetPermissionByID(ctx context.Context, id int64) (*entities.PermissionEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var perm entities.PermissionEntity
	err := r.db.QueryRowContext(ctx, "SELECT id, name, definition FROM permissions WHERE id = $1", id).
		Scan(&perm.ID, &perm.Name, &perm.Definition)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("permission not found")
	}
	if err != nil {
		return nil, err
	}
	return &perm, nil
}

func (r *PermissionRepository) GetPermissionByName(ctx context.Context, name string) (*entities.PermissionEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var perm entities.PermissionEntity
	err := r.db.QueryRowContext(ctx, "SELECT id, name, definition FROM permissions WHERE name = $1", name).
		Scan(&perm.ID, &perm.Name, &perm.Definition)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("permission not found")
	}
	if err != nil {
		return nil, err
	}
	return &perm, nil
}

func (r *PermissionRepository) GetAllPermissions(ctx context.Context) ([]entities.PermissionEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, "SELECT id, name, definition FROM permissions ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []entities.PermissionEntity
	for rows.Next() {
		var perm entities.PermissionEntity
		if err := rows.Scan(&perm.ID, &perm.Name, &perm.Definition); err != nil {
			return nil, err
		}
		permissions = append(permissions, perm)
	}
	return permissions, rows.Err()
}

func (r *PermissionRepository) GetVisiblePermissions(ctx context.Context, groupNames []string) ([]entities.PermissionEntity, error) {
	if len(groupNames) == 0 {
		return []entities.PermissionEntity{}, nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	args := make([]interface{}, len(groupNames))
	for i, groupName := range groupNames {
		args[i] = groupName
	}

	query := fmt.Sprintf(`
		SELECT DISTINCT p.id, p.name, p.definition
		FROM permissions p
		INNER JOIN permission_visibility pv ON p.id = pv.permission_id
		INNER JOIN groups g ON pv.group_id = g.id
		WHERE g.name IN (%s)
		ORDER BY p.name
	`, buildPlaceholders(1, len(groupNames)))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []entities.PermissionEntity
	for rows.Next() {
		var perm entities.PermissionEntity
		if err := rows.Scan(&perm.ID, &perm.Name, &perm.Definition); err != nil {
			return nil, err
		}
		permissions = append(permissions, perm)
	}
	return permissions, rows.Err()
}

func (r *PermissionRepository) GetGroupByID(ctx context.Context, id int64) (*entities.GroupEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var group entities.GroupEntity
	err := r.db.QueryRowContext(ctx, "SELECT id, name, definition FROM groups WHERE id = $1", id).
		Scan(&group.ID, &group.Name, &group.Definition)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("group not found")
	}
	if err != nil {
		return nil, err
	}
	return &group, nil
}

func (r *PermissionRepository) GetGroupByName(ctx context.Context, name string) (*entities.GroupEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var group entities.GroupEntity
	err := r.db.QueryRowContext(ctx, "SELECT id, name, definition FROM groups WHERE name = $1", name).
		Scan(&group.ID, &group.Name, &group.Definition)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("group not found")
	}
	if err != nil {
		return nil, err
	}
	return &group, nil
}

func (r *PermissionRepository) GetAllGroups(ctx context.Context) ([]entities.GroupEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows, err := r.db.QueryContext(ctx, "SELECT id, name, definition FROM groups ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []entities.GroupEntity
	for rows.Next() {
		var group entities.GroupEntity
		if err := rows.Scan(&group.ID, &group.Name, &group.Definition); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

func (r *PermissionRepository) IsPermissionVisibleToGroups(ctx context.Context, permissionName string, groupNames []string) (bool, error) {
	if len(groupNames) == 0 {
		return false, nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	query := fmt.Sprintf(`
		SELECT COUNT(*) > 0
		FROM permission_visibility pv
		INNER JOIN permissions p ON pv.permission_id = p.id
		INNER JOIN groups g ON pv.group_id = g.id
		WHERE p.name = $1 AND g.name IN (%s)
	`, buildPlaceholders(2, len(groupNames)))

	args := make([]interface{}, len(groupNames)+1)
	args[0] = permissionName
	for i, groupName := range groupNames {
		args[i+1] = groupName
	}

	var visible bool
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&visible)
	return visible, err
}

func (r *PermissionRepository) GetGroupsForPermission(ctx context.Context, permissionName string) ([]entities.GroupEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	query := `
		SELECT g.id, g.name, g.definition
		FROM groups g
		INNER JOIN permission_visibility pv ON g.id = pv.group_id
		INNER JOIN permissions p ON pv.permission_id = p.id
		WHERE p.name = $1
		ORDER BY g.name
	`

	rows, err := r.db.QueryContext(ctx, query, permissionName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []entities.GroupEntity
	for rows.Next() {
		var group entities.GroupEntity
		if err := rows.Scan(&group.ID, &group.Name, &group.Definition); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

// Permission visibility mappings
// Returns a map where key is permission name and value is slice of group names
func (r *PermissionRepository) GetAllPermissionVisibility(ctx context.Context) (map[string][]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	query := `
		SELECT p.name, g.name
		FROM permission_visibility pv
		INNER JOIN permissions p ON pv.permission_id = p.id
		INNER JOIN groups g ON pv.group_id = g.id
		ORDER BY p.name, g.name
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	visibilityMap := make(map[string][]string)
	for rows.Next() {
		var permName, groupName string
		if err := rows.Scan(&permName, &groupName); err != nil {
			return nil, err
		}
		visibilityMap[permName] = append(visibilityMap[permName], groupName)
	}
	return visibilityMap, rows.Err()
}

func (r *PermissionRepository) CreatePermission(ctx context.Context, name, definition string) (*entities.PermissionEntity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var id int64
	err := r.db.QueryRowContext(ctx,
		"INSERT INTO permissions (name, definition) VALUES ($1, $2) RETURNING id", name, definition).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrPermissionAlreadyExists
		}
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}

	return &entities.PermissionEntity{
		ID:         id,
		Name:       name,
		Definition: definition,
	}, nil
}

func (r *PermissionRepository) UpdatePermission(ctx context.Context, id int64, definition string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	result, err := r.db.ExecContext(ctx, "UPDATE permissions SET definition = $1 WHERE id = $2", definition, id)
	if err != nil {
		return fmt.Errorf("failed to update permission: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("permission not found")
	}

	return nil
}

func (r *PermissionRepository) DeletePermission(ctx context.Context, id int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	result, err := r.db.ExecContext(ctx, "DELETE FROM permissions WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete permission: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("permission not found")
	}

	return nil
}

func (r *PermissionRepository) CreateGroup(ctx context.Context, name, definition string) (*entities.GroupEntity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var id int64
	err := r.db.QueryRowContext(ctx,
		"INSERT INTO groups (name, definition) VALUES ($1, $2) RETURNING id", name, definition).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrGroupAlreadyExists
		}
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	return &entities.GroupEntity{
		ID:         id,
		Name:       name,
		Definition: definition,
	}, nil
}

func (r *PermissionRepository) UpdateGroup(ctx context.Context, id int64, definition string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	result, err := r.db.ExecContext(ctx, "UPDATE groups SET definition = $1 WHERE id = $2", definition, id)
	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("group not found")
	}

	return nil
}

func (r *PermissionRepository) DeleteGroup(ctx context.Context, id int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	result, err := r.db.ExecContext(ctx, "DELETE FROM groups WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("group not found")
	}

	return nil
}

func (r *PermissionRepository) AddPermissionVisibility(ctx context.Context, permissionID, groupID int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, err := r.db.ExecContext(ctx,
		"INSERT INTO permission_visibility (permission_id, group_id) VALUES ($1, $2)", permissionID, groupID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrVisibilityAlreadyExists
		}
		return fmt.Errorf("failed to add permission visibility: %w", err)
	}

	return nil
}

func (r *PermissionRepository) RemovePermissionVisibility(ctx context.Context, permissionID, groupID int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	result, err := r.db.ExecContext(ctx,
		"DELETE FROM permission_visibility WHERE permission_id = $1 AND group_id = $2", permissionID, groupID)
	if err != nil {
		return fmt.Errorf("failed to remove permission visibility: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("permission visibility mapping not found")
	}

	return nil
}

// Close is a no-op: the pool is owned by the Store that opened it, and closing
// it here would take the accounts down with the catalogue.
func (r *PermissionRepository) Close() error { return nil }

// buildPlaceholders renders "$start,$start+1,..." for an IN list.
func buildPlaceholders(start, count int) string {
	if count == 0 {
		return ""
	}
	placeholders := make([]string, count)
	for i := range placeholders {
		placeholders[i] = "$" + strconv.Itoa(start+i)
	}
	return strings.Join(placeholders, ",")
}
