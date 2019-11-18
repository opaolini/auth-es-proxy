package main

import "net/http"

type Signer interface {
	// SignRequest uses the underlying signing scheme to provide signature
	// of the body inside of a Proxy-Signature: header
	SignRequest(*http.Request) error
}
