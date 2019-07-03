package main

import (
	"fmt"
	"net/http"

	"github.com/caarlos0/env/v6"

	log "github.com/sirupsen/logrus"
)

type ProxyConfig struct {
	Port int `env:"PORT" envDefault:"3000"`

	// Proxy target
	RemoteAddress string `env:"REMOTE_ADDRESS"`

	// InputValidation enables the proxy to validate the incoming proxy
	// requests using
	InputValidation bool `env:"INPUT_VALIDATION"`
	// Allowed Public identities passed in as comma separated b64 encoded
	// pubkeys
	AllowedIDs string `env:"ALLOWED_IDS"`

	OutputSigning bool `env:"OUTPUT_SIGNING"`
	// Private Key is required when output signing is set to true
	PrivateKeyPath string `env:"PRIVATE_KEY_PATH"`
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
	if err := http.ListenAndServe(listenString, proxy); err != nil {
		log.Panic(err)
	}
}
