package main

import (
	"fmt"
	"net/http"

	"github.com/caarlos0/env/v6"

	log "github.com/sirupsen/logrus"
)

type ProxyConfig struct {
	// Port on whch the proxy is listening on
	Port int `env:"PORT" envDefault:"3000"`

	// Proxy target
	RemoteAddress string `env:"REMOTE_ADDRESS"`

	// InputValidation enables the proxy to validate / authenticate the
	// incoming proxy requests using
	InputValidation bool `env:"INPUT_VALIDATION"`

	// one of: [ "ecdsasignatures", "basicauth", "none" ]
	AuthenticationScheme string `env:"AUTHENTICATION_SCHEME" envDefault:"basicauth"`

	// if AuthenticationScheme is basicauth then this string is used for
	// determinig allowed user / password pairs.
	// NOTE: the string format is: user1:password1,user2:password2
	AllowedBasicAuthUserString string `env:"ALLOWED_USERS_STRING" envDefault:""`

	// If AuthenticationScheme is ecdsasigning then this string is used for
	// determining allowed public identities
	// NOTE: the string format is a comma separated b64 encoded pubkeys
	AllowedIDs string `env:"ALLOWED_IDS"`

	// Should the proxied request be signed by auth-es-proxy
	OutputSigning bool `env:"OUTPUT_SIGNING"`

	// Private Key is required when output signing is set to true
	PrivateKeyPath string `env:"PRIVATE_KEY_PATH"`

	// If set to an non-empty string the proxy will check whether the
	// requested path matches the this REGEX pattern otherwise returns
	// unaothrized
	AllowedPathRegex string `env:"ALLOWED_PATH_REGEX" envDefault:""`
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
