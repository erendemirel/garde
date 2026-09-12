#!/bin/sh
set -e

# Bind-mounted ./data is often owned by the host/CI user (not 65532). Fix before drop.
mkdir -p /app/data
if [ "$(id -u)" = "0" ]; then
	if ! chown -R nonroot:nonroot /app/data 2>/dev/null; then
		# chown can fail on some bind mounts (e.g. restricted Docker Desktop).
		# Allow start only if nonroot can already write — never chmod 777.
		if ! su-exec nonroot:nonroot sh -c 'touch /app/data/.garde-write-test && rm -f /app/data/.garde-write-test'; then
			echo "FATAL: /app/data is not writable by nonroot (uid 65532) and chown failed." >&2
			echo "Fix host ownership (chown -R 65532:65532 ./data) or mount permissions; refusing world-writable fallback." >&2
			exit 1
		fi
	fi
	exec su-exec nonroot:nonroot "$@"
fi

exec "$@"
