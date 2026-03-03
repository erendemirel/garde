# Vault Agent Configuration (Production)
# Authenticates via AppRole and writes one file per secret to /run/secrets (tmpfs)

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

# Static secrets: one file per key
template {
  contents = "{{ with secret \"secret/data/garde/redis_host\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/redis_host"
}

template {
  contents = "{{ with secret \"secret/data/garde/redis_port\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/redis_port"
}

template {
  contents = "{{ with secret \"secret/data/garde/redis_password\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/redis_password"
}

# Optional: dynamic Redis password from Vault database engine (uncomment and remove static redis_password block above to use)
# template {
#   source      = "/vault/config/templates/redis_password.tpl"
#   destination = "/run/secrets/redis_password"
#   error_on_missing_key = false
# }

template {
  contents = "{{ with secret \"secret/data/garde/redis_db\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/redis_db"
}

template {
  contents = "{{ with secret \"secret/data/garde/superuser_email\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/superuser_email"
}

template {
  contents = "{{ with secret \"secret/data/garde/superuser_password\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/superuser_password"
}

template {
  contents = "{{ with secret \"secret/data/garde/domain_name\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/domain_name"
}

template {
  contents = "{{ with secret \"secret/data/garde/use_tls\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/use_tls"
}

template {
  contents = "{{ with secret \"secret/data/garde/tls_cert_path\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/tls_cert_path"
}

template {
  contents = "{{ with secret \"secret/data/garde/tls_key_path\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/tls_key_path"
}

template {
  contents = "{{ with secret \"secret/data/garde/tls_ca_path\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/tls_ca_path"
}

template {
  contents = "{{ with secret \"secret/data/garde/port\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/port"
}

template {
  contents = "{{ with secret \"secret/data/garde/api_key\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/api_key"
}

template {
  contents = "{{ with secret \"secret/data/garde/admin_users_json\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/admin_users_json"
}

template {
  contents = "{{ with secret \"secret/data/garde/gin_mode\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/gin_mode"
}

template {
  contents = "{{ with secret \"secret/data/garde/cors_allow_origins\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/cors_allow_origins"
}

template {
  contents = "{{ with secret \"secret/data/garde/log_level\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/log_level"
}

template {
  contents = "{{ with secret \"secret/data/garde/enforce_mfa\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/enforce_mfa"
}

template {
  contents = "{{ with secret \"secret/data/garde/rate_limit\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/rate_limit"
}

template {
  contents = "{{ with secret \"secret/data/garde/rapid_request_config\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/rapid_request_config"
}

template {
  contents = "{{ with secret \"secret/data/garde/disable_user_agent_check\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/disable_user_agent_check"
}

template {
  contents = "{{ with secret \"secret/data/garde/disable_ip_blacklisting\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/disable_ip_blacklisting"
}

template {
  contents = "{{ with secret \"secret/data/garde/disable_multiple_ip_check\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/disable_multiple_ip_check"
}

template {
  contents = "{{ with secret \"secret/data/garde/cookie_same_site\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/cookie_same_site"
  error_on_missing_key = false
}

# SMTP (optional)
template {
  contents = "{{ with secret \"secret/data/garde/smtp_host\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/smtp_host"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/smtp_port\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/smtp_port"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/smtp_user\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/smtp_user"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/smtp_password\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/smtp_password"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/smtp_from\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/smtp_from"
  error_on_missing_key = false
}
