# Vault Agent Configuration (Production)
# Authenticates via AppRole and writes one file per secret to /run/secrets (tmpfs)

pid_file = "/tmp/vault-agent.pid"

vault {
  address = "http://vault:8200"
}

# Auto-auth with AppRole
# AppRole files are host-mounted (mode 600) and intentionally kept after read so
# vault-agent restarts can re-auth without re-running init. Rotate secret-id on
# compromise (see vault/README.md Security Notes); do not flip remove_secret_id
# or secret_id_ttl without a redistribution path.
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

# Client-certificate policy for the public listener: off (default), optional or
# required. Leave it off for anything browsers reach.
template {
  contents = "{{ with secret \"secret/data/garde/browser_mtls\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/browser_mtls"
  error_on_missing_key = false
}

# The private service listener that carries /validate. When it is on, /validate
# leaves the public listener unless public_validate says otherwise.
template {
  contents = "{{ with secret \"secret/data/garde/service_listener\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/service_listener"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/service_port\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/service_port"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/service_mtls\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/service_mtls"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/service_tls_cert_path\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/service_tls_cert_path"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/service_tls_key_path\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/service_tls_key_path"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/service_tls_ca_path\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/service_tls_ca_path"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/public_validate\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/public_validate"
  error_on_missing_key = false
}

# Whether the shared api_key authenticates /validate when that endpoint is
# served on the public listener. garde will not start without it, because one
# secret held by every caller, in front of an endpoint that can validate any
# user's session, is not a posture to inherit by accident. Set it false and
# issue per-caller keys instead; true keeps the older single-listener
# behaviour. Leave the key unset when service_listener is on.
template {
  contents = "{{ with secret \"secret/data/garde/public_validate_shared_key\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/public_validate_shared_key"
  error_on_missing_key = false
}

template {
  contents = "{{ with secret \"secret/data/garde/api_key\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/api_key"
}

template {
  contents = "{{ with secret \"secret/data/garde/mfa_encryption_key\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/mfa_encryption_key"
  error_on_missing_key = false
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
  contents = "{{ with secret \"secret/data/garde/trusted_proxies\" }}{{ .Data.data.value }}{{ end }}"
  destination = "/run/secrets/trusted_proxies"
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
