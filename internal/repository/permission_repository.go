package repository

import (
	"context"
	"database/sql"
	"fmt"
	"garde/internal/entities"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type PermissionRepository struct {
	db *sql.DB
	mu sync.RWMutex
}

var (
	permissionRepo     *PermissionRepository
	permissionRepoOnce sync.Once
)

// Singleton instance of PermissionRepository
func GetPermissionRepository() (*PermissionRepository, error) {
	var err error
	permissionRepoOnce.Do(func() {
		permissionRepo, err = NewPermissionRepository()
	})
	return permissionRepo, err
}

func NewPermissionRepository() (*PermissionRepository, error) {
	dataDir := "data"
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "permissions.db")
	db, err := sql.Open("sqlite3", dbPath+"?_mmap_size=268435456") // 256MB mmap
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable memory-mapped I/O
	if _, err := db.Exec("PRAGMA mmap_size = 268435456"); err != nil {
		return nil, fmt.Errorf("failed to set mmap_size: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	repo := &PermissionRepository{db: db}

	// Initialize schema
	if err := repo.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	slog.Info("Permission repository initialized", "db_path", dbPath)
	return repo, nil
}

func (r *PermissionRepository) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS permissions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		definition TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS groups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		definition TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS permission_visibility (
		permission_id INTEGER NOT NULL,
		group_id INTEGER NOT NULL,
		PRIMARY KEY (permission_id, group_id),
		FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
		FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_permission_visibility_permission ON permission_visibility(permission_id);
	CREATE INDEX IF NOT EXISTS idx_permission_visibility_group ON permission_visibility(group_id);
	`

	_, err := r.db.Exec(schema)
	return err
}

func (r *PermissionRepository) GetPermissionByID(ctx context.Context, id int64) (*entities.PermissionEntity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var perm entities.PermissionEntity
	err := r.db.QueryRowContext(ctx, "SELECT id, name, definition FROM permissions WHERE id = ?", id).
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
	err := r.db.QueryRowContext(ctx, "SELECT id, name, definition FROM permissions WHERE name = ?", name).
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
	`, buildPlaceholdersFixed(len(groupNames)))

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
	err := r.db.QueryRowContext(ctx, "SELECT id, name, definition FROM groups WHERE id = ?", id).
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
	err := r.db.QueryRowContext(ctx, "SELECT id, name, definition FROM groups WHERE name = ?", name).
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
		WHERE p.name = ? AND g.name IN (%s)
	`, buildPlaceholdersFixed(len(groupNames)))

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
		WHERE p.name = ?
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

	result, err := r.db.ExecContext(ctx, "INSERT INTO permissions (name, definition) VALUES (?, ?)", name, definition)
	if err != nil {
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get permission ID: %w", err)
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

	result, err := r.db.ExecContext(ctx, "UPDATE permissions SET definition = ? WHERE id = ?", definition, id)
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

	result, err := r.db.ExecContext(ctx, "DELETE FROM permissions WHERE id = ?", id)
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

	result, err := r.db.ExecContext(ctx, "INSERT INTO groups (name, definition) VALUES (?, ?)", name, definition)
	if err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get group ID: %w", err)
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

	result, err := r.db.ExecContext(ctx, "UPDATE groups SET definition = ? WHERE id = ?", definition, id)
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

	result, err := r.db.ExecContext(ctx, "DELETE FROM groups WHERE id = ?", id)
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

	_, err := r.db.ExecContext(ctx, "INSERT INTO permission_visibility (permission_id, group_id) VALUES (?, ?)", permissionID, groupID)
	if err != nil {
		return fmt.Errorf("failed to add permission visibility: %w", err)
	}

	return nil
}

func (r *PermissionRepository) RemovePermissionVisibility(ctx context.Context, permissionID, groupID int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	result, err := r.db.ExecContext(ctx, "DELETE FROM permission_visibility WHERE permission_id = ? AND group_id = ?", permissionID, groupID)
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

func (r *PermissionRepository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

func buildPlaceholdersFixed(count int) string {
	if count == 0 {
		return ""
	}
	placeholders := make([]string, count)
	for i := range placeholders {
		placeholders[i] = "?"
	}
	result := ""
	for i, p := range placeholders {
		if i > 0 {
			result += ","
		}
		result += p
	}
	return result
}
