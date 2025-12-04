# Vault Agent Configuration
# This agent authenticates to Vault and writes secrets to /run/secrets (tmpfs)

pid_file = "/tmp/vault-agent.pid"

vault {
  address = "http://vault:8200"
}

# Auto-auth with AppRole
auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "/vault/config/role-id"
      secret_id_file_path = "/vault/config/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink "file" {
    config = {
      path = "/tmp/vault-token"
    }
  }
}

# Template for Redis password(dynamic secret)
template {
  source      = "/vault/config/templates/redis_password.tpl"
  destination = "/run/secrets/redis_password"
}

# Template for static secrets
template {
  source      = "/vault/config/templates/secrets.tpl"
  destination = "/run/secrets/static"
}

