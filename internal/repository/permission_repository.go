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

// GetPermissionRepository returns a singleton instance of PermissionRepository
func GetPermissionRepository() (*PermissionRepository, error) {
	var err error
	permissionRepoOnce.Do(func() {
		permissionRepo, err = NewPermissionRepository()
	})
	return permissionRepo, err
}

func NewPermissionRepository() (*PermissionRepository, error) {
	// Create data directory if it doesn't exist
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

	// Initialize schema and sample data
	if err := repo.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	if err := repo.initSampleData(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize sample data: %w", err)
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

func (r *PermissionRepository) initSampleData() error {
	// Check if data already exists
	var count int
	err := r.db.QueryRow("SELECT COUNT(*) FROM permissions").Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		slog.Info("Sample data already exists, skipping initialization")
		return nil
	}

	// Insert sample permissions
	permissions := []struct {
		name       string
		definition string
	}{
		{"a_permission", "Ability to perform A actions"},
		{"another_permission", "Ability to perform something"},
		{"permission_b", "Users who have this permission can perform B"},
		{"some_permission", "To allow something"},
		{"admin_permission", "Administrative permission"},
		{"read_permission", "Read access permission"},
		{"write_permission", "Write access permission"},
	}

	permIDs := make(map[string]int64)
	for _, p := range permissions {
		result, err := r.db.Exec("INSERT INTO permissions (name, definition) VALUES (?, ?)", p.name, p.definition)
		if err != nil {
			return fmt.Errorf("failed to insert permission %s: %w", p.name, err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("failed to get permission ID for %s: %w", p.name, err)
		}
		permIDs[p.name] = id
	}

	// Insert sample groups
	groups := []struct {
		name       string
		definition string
	}{
		{"x", "X Group - Users of group x"},
		{"y", "Y Role - y role"},
		{"z", "Z Users - z users"},
		{"admin_group", "Administrative group"},
		{"user_group", "Regular user group"},
	}

	groupIDs := make(map[string]int64)
	for _, g := range groups {
		result, err := r.db.Exec("INSERT INTO groups (name, definition) VALUES (?, ?)", g.name, g.definition)
		if err != nil {
			return fmt.Errorf("failed to insert group %s: %w", g.name, err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("failed to get group ID for %s: %w", g.name, err)
		}
		groupIDs[g.name] = id
	}

	// Insert sample permission visibility mappings
	visibility := []struct {
		permission string
		groups     []string
	}{
		{"a_permission", []string{"x", "z"}},
		{"another_permission", []string{"y"}},
		{"permission_b", []string{}},                 // No groups - not visible to anyone
		{"some_permission", []string{"x", "y", "z"}}, // Visible to all groups
		{"admin_permission", []string{"admin_group"}},
		{"read_permission", []string{"user_group", "admin_group"}},
		{"write_permission", []string{"admin_group"}},
	}

	for _, v := range visibility {
		permID := permIDs[v.permission]
		for _, groupName := range v.groups {
			groupID := groupIDs[groupName]
			_, err := r.db.Exec("INSERT INTO permission_visibility (permission_id, group_id) VALUES (?, ?)", permID, groupID)
			if err != nil {
				return fmt.Errorf("failed to insert visibility for permission %s to group %s: %w", v.permission, groupName, err)
			}
		}
	}

	slog.Info("Sample data initialized successfully")
	return nil
}

// GetPermissionByID retrieves a permission by ID
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

// GetPermissionByName retrieves a permission by name
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

// GetAllPermissions retrieves all permissions
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

// GetVisiblePermissions retrieves permissions visible to the given groups
func (r *PermissionRepository) GetVisiblePermissions(ctx context.Context, groupNames []string) ([]entities.PermissionEntity, error) {
	if len(groupNames) == 0 {
		return []entities.PermissionEntity{}, nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Build query with placeholders
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

// GetGroupByID retrieves a group by ID
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

// GetGroupByName retrieves a group by name
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

// GetAllGroups retrieves all groups
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

// IsPermissionVisibleToGroups checks if a permission is visible to any of the given groups
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

// GetGroupsForPermission retrieves all groups that can see a permission
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

// Close closes the database connection
func (r *PermissionRepository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

// Helper function to build SQL placeholders
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
