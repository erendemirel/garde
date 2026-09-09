# Caddy with every DNS-01 provider module the cluster may need compiled in.
# sync-config picks which acme_dns block to render from DNS_PROVIDER; the
# unused modules simply sit idle in the binary.
#
# Built in CI and shipped to the hosts with `docker save` over SSH, so the
# hosts never need a registry credential or a compiler.
#
# Adding a hosting provider means adding its caddy-dns module here (and a
# matching branch in sync-config.sh). netcup needs Caddy >= 2.10 / Go >= 1.24;
# route53 needs v1.6+ for the same Caddy line.

FROM caddy:2.10-builder AS builder

ENV GOTOOLCHAIN=auto

RUN xcaddy build \
    --with github.com/caddy-dns/netcup \
    --with github.com/caddy-dns/route53@v1.6.0

FROM caddy:2.10-alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Config is bind-mounted at /etc/caddy/Caddyfile by the app compose stack.
