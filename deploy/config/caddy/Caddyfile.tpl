# Public edge for the floating-IP lane. Runs on both app nodes; only the one
# holding the failover address actually receives traffic.
#
# The managed-load-balancer lane uses Caddyfile.lb.tpl instead, where the
# platform terminates TLS and this file's ACME machinery has nothing to do.
#
# Certificates are issued over DNS-01, not HTTP-01. That is deliberate: the
# standby has no public traffic routed to it, so it could never answer an
# HTTP-01 challenge, and its certificates would go stale exactly when failover
# needs them. The ACME DNS block below is selected by DNS_PROVIDER (defaults to
# PROVIDER) when sync-config renders this file — each hosting provider uses its
# own DNS API.
#
# Sites are matched by Host header, so hitting a node's raw address does not
# serve the application.

{
	email {$ACME_EMAIL}

@@ACME_DNS_BLOCK@@
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

# /validate validates any user's session for a calling service, so it belongs
# on the private service listener, not on the hostname browsers reach. garde is
# configured not to serve it here either; this is the second lock, so a Vault
# key flipped by mistake does not silently publish the endpoint.
#
# Deployments with external callers set PUBLIC_VALIDATE=true in the inventory,
# and sync-config drops the import below. The endpoint then answers here, but
# only to a per-tenant API key — the shared key is refused on this listener.
(no_public_validate) {
	handle /validate* {
		respond 404
	}
}

{$APP_DOMAIN} {
	import hardening
	encode zstd gzip
	reverse_proxy ui:80
	log {
		output stdout
		format json
	}
}

{$API_DOMAIN} {
	import hardening
	encode zstd gzip

	import no_public_validate

	# garde runs with use_tls=false behind this proxy. Set cookie_secure=true
	# and trusted_proxies to the compose subnet in Vault so X-Forwarded-For is
	# honoured and session cookies keep the Secure flag.
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
