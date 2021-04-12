package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/caarlos0/env/v6"

	log "github.com/sirupsen/logrus"
)

type ProxyConfig struct {
	// Port on which the proxy is listening on
	Port int `env:"PORT" envDefault:"3000"`

	// Proxy target
	RemoteAddress string `env:"REMOTE_ADDRESS"`

	// ShouldValidateRequests enables the proxy to validate / authenticate the
	// incoming proxy requests using
	ShouldValidateRequests bool `env:"SHOULD_VALIDATE_REQUESTS"`

	// one of: [ "ECDSA_SIGNATURE_SCHEME", "BASIC_AUTH_SCHEME", "NO_AUTH_SCHEME" ]
	AuthenticationScheme string `env:"AUTHENTICATION_SCHEME" envDefault:"BASIC_AUTH_SCHEME"`

	// if AuthenticationScheme is BASIC_AUTH_SCHEME then this string is used for
	// determining allowed user / password pairs.
	// NOTE: the string format is: user1:password1,user2:password2
	AllowedBasicAuthUserString string `env:"ALLOWED_USERS_BASIC_AUTH_STRING" envDefault:""`

	// If AuthenticationScheme is ECDSA_SIGNATURE_SCHEME then this string is
	// used for determining allowed public identities
	// NOTE: the string format is a comma separated b64 encoded pubkeys
	AllowedIDs string `env:"ALLOWED_IDS"`

	// Should the proxied request be signed by auth-es-proxy
	ShouldSignOutgoing bool `env:"SHOULD_SIGN_OUTGOING"`

	// SigningScheme sets which signing scheme should be used if
	// ShouldSignOutgoing is set to true
	// NOTE: uses the same schemes as AuthenticationScheme
	SigningScheme string `env:"SIGNING_SCHEME" envDefault:"NO_AUTH_SCHEME"`

	// Private Key is required when output signing is set to true and
	// SigningScheme is ECDSA_SIGNATURE_SCHEME
	PrivateKeyPath string `env:"PRIVATE_KEY_PATH"`

	// BasicAuthUser is the Basic Authentication username when using
	// BASIC_AUTH_SCHEME and output signing is set to true
	BasicAuthUser string `env:"BASIC_AUTH_USER" envDefault:""`

	// BasicAuthPassword is the Basic Authentication password when using
	// BASIC_AUTH_SCHEME and output signing is set to true
	BasicAuthPassword string `env:"BASIC_AUTH_PASSWORD" envDefault:""`

	// If set to a non-empty string the proxy will check whether the
	// requested path matches this REGEX pattern otherwise returns
	// unauthorized
	AllowedPathRegex string `env:"ALLOWED_PATH_REGEX" envDefault:""`

	// Response timeout for proxy requests
	ResponseTimeout time.Duration `env:"RESPONSE_TIMEOUT" envDefault:"60s"`
}

func main() {
	log.SetFormatter(&log.JSONFormatter{})

	cfg := ProxyConfig{}
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("could not parse config: %s", err)
	}

	proxy, err := NewProxy(&cfg)
	if err != nil {
		log.Fatalf("failed to create a new proxy: %s", err)
	}

	listenString := fmt.Sprintf(":%d", cfg.Port)
	log.Infof("starting proxy on: %s", listenString)
	if err := http.ListenAndServe(listenString, proxy); err != nil {
		log.Panic(err)
	}
}
