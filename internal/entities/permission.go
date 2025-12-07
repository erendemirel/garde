package entities

// PermissionEntity represents a permission in the database
type PermissionEntity struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Definition string `json:"definition"`
}

// GroupEntity represents a group in the database
type GroupEntity struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Definition string `json:"definition"`
}

