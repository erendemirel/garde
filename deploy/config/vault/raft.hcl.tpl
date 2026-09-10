# Vault server config - Integrated Storage (Raft), one member per host.
# Rendered per node by deploy/scripts/sync-config.sh, which substitutes the
# double-at placeholders below. Do not edit the rendered copy on the host.
#
# TLS is disabled on the listener because every byte between members already
# travels inside the WireGuard mesh, and the listener is bound to the mesh
# address only. Never publish 8200/8201 to a public interface.

storage "raft" {
  # /vault/file, not /vault/data: the only storage path the image prepares and
  # its entrypoint chowns. See the note in deploy/compose/vault-node.yml.
  path    = "/vault/file"
  node_id = "@@VAULT_NODE_ID@@"

@@RETRY_JOIN@@
}

@@SEAL_BLOCK@@

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_disable     = 1

  # Prometheus scrapes this over the mesh; the listener is not publicly bound.
  telemetry {
    unauthenticated_metrics_access = true
  }
}

# Advertised addresses must be the mesh IPs so peers can reach this member.
api_addr     = "http://@@NODE_WG_IP@@:8200"
cluster_addr = "http://@@NODE_WG_IP@@:8201"

cluster_name = "garde-vault"
ui           = true

# Required in most container environments even with IPC_LOCK granted.
disable_mlock = true

telemetry {
  prometheus_retention_time = "24h"
  disable_hostname          = true
}
