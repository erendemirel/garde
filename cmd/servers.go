package main

import (
	"log/slog"
	"net/http"
	"strings"

	"garde/internal/httpmount"
	"garde/pkg/config"
	"garde/pkg/tlsconfig"
)

// newPublicServer builds the listener browsers and external API clients reach.
func newPublicServer(handler http.Handler) (*http.Server, error) {
	port := config.GetWithDefault("PORT", "8443")
	srv := newHTTPServer(":"+port, handler)

	if !config.GetBool("USE_TLS") {
		slog.Warn("Starting public listener without TLS", "port", port)
		return srv, nil
	}

	tlsConfig, err := tlsconfig.Build(
		config.Get("TLS_CERT_PATH"),
		config.Get("TLS_KEY_PATH"),
		strings.TrimSpace(config.Get("TLS_CA_PATH")),
		config.BrowserMTLS(),
		"public",
	)
	if err != nil {
		return nil, err
	}
	srv.TLSConfig = tlsConfig

	slog.Info("Starting public listener with TLS", "port", port, "browser_mtls", config.BrowserMTLS().String())
	return srv, nil
}

// newServiceServer builds the private listener: /validate, admin/superuser, and
// (when the public kill switch is on) the full external user auth surface.
func newServiceServer(engineDeps *routerDeps, mounts *httpmount.Deps) (*http.Server, error) {
	policy := config.ServiceMTLS()
	router := newEngine(engineDeps)
	httpmount.MountServiceListener(router, mounts)

	tlsConfig, err := tlsconfig.Build(
		config.ServiceTLSCertPath(),
		config.ServiceTLSKeyPath(),
		config.ServiceTLSCAPath(),
		policy,
		"service",
	)
	if err != nil {
		return nil, err
	}

	port := config.ServicePort()
	srv := newHTTPServer(config.ServiceBind()+":"+port, router)
	srv.TLSConfig = tlsConfig

	if policy != config.ClientCertRequired {
		slog.Warn("Service listener does not require client certificates — keep it on a private network",
			"port", port)
	}
	slog.Info("Starting service listener with TLS", "port", port, "service_mtls", policy.String())
	return srv, nil
}
