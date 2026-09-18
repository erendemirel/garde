package repository

import (
	"os"
	"path/filepath"
	"testing"

	"garde/pkg/config"
)

func initRedisSecrets(t *testing.T, secrets map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, value := range secrets {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := config.Init(dir); err != nil {
		t.Fatal(err)
	}
}

func TestRedisTLSEnabledDefaultOff(t *testing.T) {
	initRedisSecrets(t, map[string]string{
		"redis_host": "redis.example",
		"redis_port": "6379",
	})
	if redisTLSEnabled() {
		t.Fatal("REDIS_TLS default should be off")
	}
	opts := redisClientOptions("redis.example", "6379", 0)
	if opts.TLSConfig != nil {
		t.Fatal("TLSConfig should be nil when REDIS_TLS is unset")
	}
}

func TestRedisTLSEnabledByFlag(t *testing.T) {
	initRedisSecrets(t, map[string]string{"redis_tls": "true"})
	if !redisTLSEnabled() {
		t.Fatal("REDIS_TLS=true should enable TLS")
	}
	opts := redisClientOptions("redis.example", "6379", 0)
	if opts.TLSConfig == nil {
		t.Fatal("TLSConfig required when REDIS_TLS=true")
	}
	if opts.TLSConfig.ServerName != "redis.example" {
		t.Fatalf("ServerName = %q, want redis.example", opts.TLSConfig.ServerName)
	}
}

func TestRedisTLSEnabledByRedissURL(t *testing.T) {
	initRedisSecrets(t, map[string]string{
		"redis_url": "rediss://user:pass@cache.example:6380/0",
	})
	if !redisTLSEnabled() {
		t.Fatal("rediss:// REDIS_URL should enable TLS")
	}
}
