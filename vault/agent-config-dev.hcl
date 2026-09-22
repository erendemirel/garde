# Vault Agent Configuration for Development
# Uses dev token for simplicity(no AppRole needed)

pid_file = "/tmp/vault-agent.pid"

vault {
  address = "http://dev-vault:8200"
}

# Use static token for dev (written by init-vault.sh into the shared volume)
auto_auth {
  method "token_file" {
    config = {
      token_file_path = "/vault/config/token/dev-token"
    }
  }

  sink "file" {
    config = {
      path = "/tmp/vault-token"
    }
  }
}

# Template for all secrets. Writes each secret to a separate file
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

template {
  contents = "{{ with secret \"secret/data/garde/redis_db\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/redis_db"
}

template {
  contents = "{{ with secret \"secret/data/garde/redis_tls\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/redis_tls"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/database_url\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/database_url"
}

template {
  contents = "{{ with secret \"secret/data/garde/postgres_host\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/postgres_host"
}

template {
  contents = "{{ with secret \"secret/data/garde/postgres_port\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/postgres_port"
}

template {
  contents = "{{ with secret \"secret/data/garde/postgres_user\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/postgres_user"
}

template {
  contents = "{{ with secret \"secret/data/garde/postgres_password\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/postgres_password"
}

template {
  contents = "{{ with secret \"secret/data/garde/postgres_db\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/postgres_db"
}

template {
  contents = "{{ with secret \"secret/data/garde/postgres_sslmode\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/postgres_sslmode"
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
  contents = "{{ with secret \"secret/data/garde/mfa_encryption_key\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/mfa_encryption_key"
}

template {
  contents = "{{ with secret \"secret/data/garde/admin_users_json\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/admin_users_json"
}

# Optional. Absent means every admin keeps the full admin bundle, which is the
# behaviour that predates admin scopes. Present, it narrows the admins it
# names: {"helpdesk@example.com":["garde:users:read","garde:users:write"]}
template {
  contents = "{{ with secret \"secret/data/garde/admin_scopes_json\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/admin_scopes_json"
  error_on_missing_key = false
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

# Registration / public surface. Absent → code defaults (self-service on,
# admin approval off, email verification on).
template {
  contents = "{{ with secret \"secret/data/garde/public_self_service\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/public_self_service"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/require_admin_approval\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/require_admin_approval"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/require_email_verification\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/require_email_verification"
  error_on_missing_key = false
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
  contents = "{{ with secret \"secret/data/garde/enable_swagger\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/enable_swagger"
  error_on_missing_key = false
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

template {
  contents = "{{ with secret \"secret/data/garde/cookie_secure\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/cookie_secure"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/session_idle_timeout\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/session_idle_timeout"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/session_absolute_timeout\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/session_absolute_timeout"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/session_max_active\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/session_max_active"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/trusted_proxies\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/trusted_proxies"
  error_on_missing_key = false
}

# SMTP settings (optional)
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

# Cap captcha (optional). Leave unset / cap_enabled=false to skip challenges.
template {
  contents = "{{ with secret \"secret/data/garde/cap_enabled\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/cap_enabled"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/cap_site_key\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/cap_site_key"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/cap_secret_key\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/cap_secret_key"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/cap_api_url\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/cap_api_url"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/cap_public_url\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/cap_public_url"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/cap_bypass_token\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/cap_bypass_token"
  error_on_missing_key = false
}

