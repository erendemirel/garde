# Caddy with the netcup DNS provider compiled in, so both app nodes can solve
# ACME DNS-01 challenges without holding the public failover IP.
#
# Built in CI and shipped to the hosts with `docker save` over SSH, so the
# hosts never need a registry credential or a compiler.

FROM caddy:2.8-builder AS builder

RUN xcaddy build \
    --with github.com/caddy-dns/netcup

FROM caddy:2.8-alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Config is bind-mounted at /etc/caddy/Caddyfile by the app compose stack.
