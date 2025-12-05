package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	DefaultSecretsDir = "/run/secrets"
)

var (
	secretsDir     string
	secrets        = make(map[string]string)
	secretsMu      sync.RWMutex
	initialized    bool
	watcher        *fsnotify.Watcher
	configWatcher  *fsnotify.Watcher
	onReloadHook   func()                  // Called when secrets are reloaded
	onConfigReload func(configFile string) // Called when config files change
)

// Initialize the config loader with the secrets directory
// secretsPath should be a tmpfs mount for security
func Init(secretsPath string) error {
	if secretsPath == "" {
		secretsPath = DefaultSecretsDir
	}

	info, err := os.Stat(secretsPath)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("secrets directory not found: %s", secretsPath)
	}

	secretsDir = secretsPath
	slog.Info("Config: Using secrets directory", "path", secretsDir)

	// Load all secrets initially
	if err := loadAllSecrets(); err != nil {
		return fmt.Errorf("failed to load secrets: %w", err)
	}

	initialized = true
	return nil
}

// For secret file changes (hot reload)
func StartWatcher() error {
	if !initialized {
		return fmt.Errorf("config not initialized")
	}

	var err error
	watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
					slog.Info("Config: Secret file changed, reloading", "file", filepath.Base(event.Name))

					time.Sleep(100 * time.Millisecond)

					if err := loadAllSecrets(); err != nil {
						slog.Error("Config: Failed to reload secrets", "error", err)
					} else {
						slog.Info("Config: Secrets reloaded successfully")
						if onReloadHook != nil {
							onReloadHook()
						}
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				slog.Error("Config: Watcher error", "error", err)
			}
		}
	}()

	if err := watcher.Add(secretsDir); err != nil {
		return fmt.Errorf("failed to watch secrets directory: %w", err)
	}

	slog.Info("Config: Watching for secret changes", "path", secretsDir)
	return nil
}

// To refresh connections (e.g., Redis reconnect with new password)
func SetReloadHook(hook func()) {
	onReloadHook = hook
}

func StopWatcher() {
	if watcher != nil {
		watcher.Close()
	}
	if configWatcher != nil {
		configWatcher.Close()
	}
}

func StartConfigWatcher(configsDir string, reloadCallback func(configFile string)) error {
	if configsDir == "" {
		configsDir = "configs"
	}

	info, err := os.Stat(configsDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("configs directory not found: %s", configsDir)
	}

	configWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create config watcher: %w", err)
	}

	onConfigReload = reloadCallback

	go func() {
		for {
			select {
			case event, ok := <-configWatcher.Events:
				if !ok {
					return
				}
				if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
					fileName := filepath.Base(event.Name)
					// Only react to .json files
					if strings.HasSuffix(fileName, ".json") {
						slog.Info("Config: Config file changed, reloading", "file", fileName)

						// Small delay to ensure file write is complete
						time.Sleep(100 * time.Millisecond)

						if onConfigReload != nil {
							onConfigReload(fileName)
						}
					}
				}
			case err, ok := <-configWatcher.Errors:
				if !ok {
					return
				}
				slog.Error("Config: Config watcher error", "error", err)
			}
		}
	}()

	if err := configWatcher.Add(configsDir); err != nil {
		return fmt.Errorf("failed to watch configs directory: %w", err)
	}

	slog.Info("Config: Watching for config file changes", "path", configsDir)
	return nil
}

func loadAllSecrets() error {
	entries, err := os.ReadDir(secretsDir)
	if err != nil {
		return err
	}

	newSecrets := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Skip hidden files and .gitkeep
		if strings.HasPrefix(name, ".") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(secretsDir, name))
		if err != nil {
			slog.Warn("Config: Failed to read secret file", "file", name, "error", err)
			continue
		}

		// Store with uppercase key (e.g., "redis_password" -> "REDIS_PASSWORD")
		key := strings.ToUpper(name)
		newSecrets[key] = strings.TrimSpace(string(data))
	}

	secretsMu.Lock()
	secrets = newSecrets
	secretsMu.Unlock()

	slog.Debug("Config: Loaded secrets", "count", len(newSecrets))
	return nil
}

func Get(key string) string {
	return GetWithDefault(key, "")
}

func GetWithDefault(key, defaultValue string) string {
	if !initialized {
		slog.Error("Config not initialized - call config.Init() first")
		return defaultValue
	}

	secretsMu.RLock()
	defer secretsMu.RUnlock()

	if value, exists := secrets[strings.ToUpper(key)]; exists && value != "" {
		return value
	}
	return defaultValue
}

func GetBool(key string) bool {
	value := strings.ToLower(Get(key))
	return value == "true" || value == "1" || value == "yes"
}

func GetBoolWithDefault(key string, defaultValue bool) bool {
	value := Get(key)
	if value == "" {
		return defaultValue
	}
	lowerValue := strings.ToLower(value)
	return lowerValue == "true" || lowerValue == "1" || lowerValue == "yes"
}

func MustGet(key string) string {
	value := Get(key)
	if value == "" {
		panic("Required configuration key not found in secrets: " + key)
	}
	return value
}

func GetSecretsDir() string {
	return secretsDir
}

func GetAdminUsersMap() map[string]string {
	raw := Get("ADMIN_USERS_JSON")
	if raw == "" {
		return nil
	}

	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		if fallback, ok := parseAdminUsersFallback(raw); ok {
			return fallback
		}
		slog.Warn("Config: Failed to parse ADMIN_USERS_JSON", "error", err)
		return nil
	}
	return m
}

// parseAdminUsersFallback parses "email:pwd,email2:pwd2" or "email=pwd" style strings.
func parseAdminUsersFallback(raw string) (map[string]string, bool) {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, "{}")
	items := strings.Split(raw, ",")
	result := make(map[string]string)
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		trimmed = strings.Trim(trimmed, "\"")
		if trimmed == "" {
			continue
		}
		sep := ":"
		if strings.Contains(trimmed, "=") && !strings.Contains(trimmed, ":") {
			sep = "="
		}
		parts := strings.SplitN(trimmed, sep, 2)
		if len(parts) != 2 {
			return nil, false
		}
		email := strings.TrimSpace(strings.Trim(parts[0], "\""))
		pwd := strings.TrimSpace(strings.Trim(parts[1], "\""))
		if email == "" || pwd == "" {
			return nil, false
		}
		result[email] = pwd
	}
	if len(result) == 0 {
		return nil, false
	}
	return result, true
}
