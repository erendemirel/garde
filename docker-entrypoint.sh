#!/bin/sh
set -e

# Bind-mounted ./data is often owned by the host/CI user (not 65532). Fix before drop.
mkdir -p /app/data
if [ "$(id -u)" = "0" ]; then
	chown -R nonroot:nonroot /app/data 2>/dev/null || chmod 777 /app/data 2>/dev/null || true
	exec su-exec nonroot:nonroot "$@"
fi

exec "$@"
