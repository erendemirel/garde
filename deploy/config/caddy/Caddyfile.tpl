# Public edge. Runs on both app nodes; only the one holding the failover
# address actually receives traffic.
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

	# garde runs with use_tls=false behind this proxy. Set cookie_secure=true
	# and trusted_proxies to the compose subnet in Vault so X-Forwarded-For is
	# honoured and session cookies keep the Secure flag.
	reverse_proxy garde:8443 {
		header_up X-Forwarded-Proto https
	}

	log {
		output stdout
		format json
	}
}
