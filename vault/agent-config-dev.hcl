# Vault Agent Configuration for Development
# Uses dev token for simplicity(no AppRole needed)

pid_file = "/tmp/vault-agent.pid"

vault {
  address = "http://dev-vault:8200"
}

# Use static token for dev(the dev server token)
auto_auth {
  method "token_file" {
    config = {
      token_file_path = "/vault/config/dev-token"
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
  contents = "{{ with secret \"secret/data/garde/superuser_email\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/superuser_email"
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
  contents = "{{ with secret \"secret/data/garde/admin_users\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/admin_users"
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

