package config

import (
	"log/slog"
	"strings"
)

// Client-certificate policy, resolved separately for the two audiences garde
// serves. They are separate because a single process-wide switch cannot express
// the only layout that is both secure and usable: browsers must never be asked
// for a certificate, while services calling /validate should have to present
// one.
type ClientCertPolicy int

const (
	ClientCertOff ClientCertPolicy = iota
	ClientCertOptional
	ClientCertRequired
)

func (p ClientCertPolicy) String() string {
	switch p {
	case ClientCertOptional:
		return "optional"
	case ClientCertRequired:
		return "required"
	default:
		return "off"
	}
}

const defaultServicePort = "8444"

func parseClientCertPolicy(key string, fallback ClientCertPolicy, allowOptional bool) ClientCertPolicy {
	raw := strings.ToLower(strings.TrimSpace(Get(key)))
	switch raw {
	case "":
		return fallback
	case "off", "false", "none", "disabled":
		return ClientCertOff
	case "optional":
		if !allowOptional {
			slog.Warn("Config: 'optional' is not a valid client certificate policy here, using required",
				"key", key)
			return ClientCertRequired
		}
		return ClientCertOptional
	case "required", "true", "on":
		return ClientCertRequired
	default:
		slog.Warn("Config: unknown client certificate policy, using default",
			"key", key, "value", raw, "default", fallback.String())
		return fallback
	}
}

// BrowserMTLS governs client certificates on the public listener. It defaults
// to off: a public login page that demands a certificate locks out every normal
// user. Set it only for a host that exists to serve certificate holders.
//
// Off still means "verify a certificate if one is presented" whenever a client
// CA is configured, because that is what lets /validate require mTLS on a
// single-listener deployment.
func BrowserMTLS() ClientCertPolicy {
	return parseClientCertPolicy("BROWSER_MTLS", ClientCertOff, true)
}

// ServiceMTLS governs client certificates on the private service listener.
// Required is the default: the listener exists to carry machine traffic, and
// "optional" would leave the API key as the only barrier on the one endpoint
// that can validate any user's session.
func ServiceMTLS() ClientCertPolicy {
	return parseClientCertPolicy("SERVICE_MTLS", ClientCertRequired, false)
}

// ServiceListenerEnabled turns on the second listener that carries /validate.
// Off by default so existing single-listener deployments keep working.
func ServiceListenerEnabled() bool {
	return GetBool("SERVICE_LISTENER")
}

func ServicePort() string {
	return GetWithDefault("SERVICE_PORT", defaultServicePort)
}

// ServiceBind is the interface the service listener binds to. Empty means all
// interfaces, which is what the container wants: the compose file publishes the
// port on the mesh address only, so the host — not the process — decides who
// can reach it.
func ServiceBind() string {
	return strings.TrimSpace(Get("SERVICE_BIND"))
}

func ServiceTLSCertPath() string { return strings.TrimSpace(Get("SERVICE_TLS_CERT_PATH")) }
func ServiceTLSKeyPath() string  { return strings.TrimSpace(Get("SERVICE_TLS_KEY_PATH")) }
func ServiceTLSCAPath() string   { return strings.TrimSpace(Get("SERVICE_TLS_CA_PATH")) }

// PublicValidateEnabled decides whether /validate is also mounted on the public
// listener. Enabling the service listener moves the endpoint by default: having
// it answer on both is the exposure the split exists to remove.
func PublicValidateEnabled() bool {
	if raw := strings.TrimSpace(Get("PUBLIC_VALIDATE")); raw != "" {
		return GetBool("PUBLIC_VALIDATE")
	}
	return !ServiceListenerEnabled()
}

// PublicValidateMTLS reports the policy /validate enforces when it is served on
// the public listener.
//
// Built-in TLS plus a client CA is the long-standing signal that service calls
// arrive with certificates, but only in single-listener deployments: once the
// service listener exists, the operator's own services are over there, and a
// public /validate is there for external callers who have no certificate to
// present. Demanding one would lock out exactly the audience it was published
// for. An explicit BROWSER_MTLS=required still forces it, because that says the
// whole listener exists to serve certificate holders.
func PublicValidateMTLS() ClientCertPolicy {
	if BrowserMTLS() == ClientCertRequired {
		return ClientCertRequired
	}
	if !ServiceListenerEnabled() && GetBool("USE_TLS") && strings.TrimSpace(Get("TLS_CA_PATH")) != "" {
		return ClientCertRequired
	}
	return ClientCertOff
}

// PublicValidateSharedKeyKey decides whether the shared API_KEY authenticates
// /validate when that endpoint is served on the public listener.
//
// There is no default. Accepting one long-lived secret, held by every caller,
// in front of an endpoint that can validate any user's session, is the weakest
// posture garde can serve, and it used to be the one an operator got by doing
// nothing at all. ValidateConfig refuses to start until the deployment says
// which way it wants, so the weak posture is at least a decision someone made.
const PublicValidateSharedKeyKey = "PUBLIC_VALIDATE_SHARED_KEY"

// PublicValidateSharedKey reports the operator's decision: whether the shared
// key is allowed, whether the key was set at all, and whether its value parsed.
//
// Unlike GetBool, an unrecognised value is reported rather than read as false.
// Guessing here would mean a typo silently choosing a posture, and both
// postures are wrong to choose by accident: one exposes the endpoint, the other
// breaks every caller.
func PublicValidateSharedKey() (allow, configured, valid bool) {
	switch strings.ToLower(strings.TrimSpace(Get(PublicValidateSharedKeyKey))) {
	case "":
		return false, false, true
	case "true", "1", "yes", "on":
		return true, true, true
	case "false", "0", "no", "off":
		return false, true, true
	default:
		return false, true, false
	}
}

// PublicValidateLegacyKey reports whether the shared API_KEY authenticates
// /validate on the public listener.
//
// Once the private service listener is carrying internal callers, the public
// copy exists for external tenants, and one secret shared by all of them is
// precisely the exposure the split was made to remove. There it accepts
// per-tenant keys only, whatever the setting says — which is why setting it
// there is a startup error rather than something quietly ignored.
//
// Otherwise the answer is the operator's. An unset or unparseable value is
// refused at startup, so reaching it here means something skipped validation;
// returning false then keeps the accident on the safe side, where callers get
// 401s instead of the internet getting a session validator.
func PublicValidateLegacyKey() bool {
	if ServiceListenerEnabled() {
		return false
	}
	allow, configured, valid := PublicValidateSharedKey()
	return configured && valid && allow
}
