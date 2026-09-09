# Prometheus config for the witness node. Rendered by sync-config.sh.
# Every target is a WireGuard address; nothing is scraped over the internet.

global:
  scrape_interval: 30s
  evaluation_interval: 30s
  external_labels:
    cluster: garde

rule_files:
  - /etc/prometheus/alerts.yml

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ["127.0.0.1:9090"]

  - job_name: node
    static_configs:
@@NODE_EXPORTER_TARGETS@@

  - job_name: cadvisor
    static_configs:
@@CADVISOR_TARGETS@@

  # Vault exposes telemetry unauthenticated on the mesh-bound listener.
  - job_name: vault
    metrics_path: /v1/sys/metrics
    params:
      format: ["prometheus"]
    static_configs:
@@VAULT_TARGETS@@

# Caddy is deliberately not scraped: its metrics live on the admin API, which
# can also rewrite the running config. Publishing that port, even on the mesh,
# buys little and widens the blast radius. Container health comes from cadvisor.
