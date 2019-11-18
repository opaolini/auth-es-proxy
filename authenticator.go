package main

import "net/http"

const (
	BasicAuthScheme      = "BASIC_AUTH_SCHEME"
	EcdsaSignatureScheme = "ECDSA_SIGNATURE_SCHEME"
	NoAuth               = "NO_AUTH_SCHEME"
)

type Authenticator interface {
	AuthenticateRequest(r *http.Request) error
}
