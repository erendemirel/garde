# Public edge for the managed-load-balancer lane (AWS, GCP).
#
# The difference from Caddyfile.tpl is narrow but load-bearing: the platform's
# load balancer terminates TLS with a certificate it manages itself, so this
# Caddy never proves domain control and never holds a private key. It keeps the
# one job a load balancer listener rule does badly — deciding, by Host header,
# whether a request belongs to the UI or to the API — which is why the two
# lanes still share a Caddyfile shape and the same rules about /validate.
#
# Reached only from the load balancer: the firewall admits :80 from
# LB_SOURCE_CIDRS, and 443 is bound to loopback so nothing answers it publicly.

{
	# No ACME. Issuing certificates here would be redundant at best, and at
	# worst the standby would fail challenges it has no way to answer.
	auto_https off

	# The load balancer is the only thing that talks to this listener, so it is
	# the only source whose X-Forwarded-For may be believed. Without this Caddy
	# would either drop the client address or accept a spoofed one.
	servers {
		trusted_proxies static {$LB_TRUSTED_PROXIES}
	}
}

(hardening) {
	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		X-Frame-Options "DENY"
		Referrer-Policy "strict-origin-when-cross-origin"
		-Server
	}
}

# Same reasoning as the floating-IP lane: the service endpoint is not published
# on a public hostname, whatever garde itself is configured to serve.
# PUBLIC_VALIDATE=true in the inventory drops the import, for deployments whose
# external tenants call it with a per-tenant API key.
(no_public_validate) {
	handle /validate* {
		respond 404
	}
}

http://{$APP_DOMAIN} {
	import hardening
	encode zstd gzip
	reverse_proxy ui:80
	log {
		output stdout
		format json
	}
}

http://{$API_DOMAIN} {
	import hardening
	encode zstd gzip

	import no_public_validate

	# The load balancer terminated HTTPS, so the scheme the user saw is https
	# even though this hop is plaintext inside the VPC. garde needs that to
	# keep issuing Secure cookies.
	handle {
		reverse_proxy garde:8443 {
			header_up X-Forwarded-Proto https
		}
	}

	log {
		output stdout
		format json
	}
}

# Health checks arrive with the target's address in the Host header, not a
# domain, so they need a site that matches anything. Proxying to garde's own
# /health is deliberate: a node whose API is broken should leave the pool, and
# a static 200 here would keep it in.
:80 {
	handle /healthz {
		rewrite * /health
		reverse_proxy garde:8443
	}

	handle {
		respond 404
	}
}
