# Vault server config for the single-VPS production Compose stack.
# This is a real (non-dev-mode) Vault: data is persisted, and the operator
# must initialize + unseal before AppRole init or the agent can start.
#
# TLS between containers on the internal Docker network is optional; terminate
# TLS at your reverse proxy for external traffic. Do not publish port 8200
# to the public internet.

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

api_addr     = "http://vault:8200"
cluster_addr = "http://vault:8201"

ui = true

# Required in many container environments even with IPC_LOCK.
disable_mlock = true
