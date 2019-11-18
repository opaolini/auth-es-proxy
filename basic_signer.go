package main

import (
	"errors"
	"net/http"
)

var (
	ErrBasicAuthUserEmpty     = errors.New("basic auth username for output signing is empty")
	ErrBasicAuthPasswordEmpty = errors.New("basic auth password for output signing is empty")
)

// NewBasicAuthSigner returns a new Signer which adds a Basic Auth header to requests.
func NewBasicAuthSigner(username, password string) (*BasicAuthSigner, error) {
	if username == "" {
		return nil, ErrBasicAuthUserEmpty
	}

	if password == "" {
		return nil, ErrBasicAuthPasswordEmpty
	}

	return &BasicAuthSigner{
		username: username,
		password: password,
	}, nil

}

type BasicAuthSigner struct {
	username string
	password string
}

func (b *BasicAuthSigner) SignRequest(r *http.Request) error {
	r.SetBasicAuth(b.username, b.password)
	return nil
}
