package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	p2pcrypto "github.com/libp2p/go-libp2p-crypto"
)

var (
	ErrMissingProxyIDHeader        = errors.New("missing Proxy-ID request header")
	ErrFailedToReadRequestBody     = errors.New("failed to read request body")
	ErrMissingSignatureFromRequest = errors.New("missing Proxy-Signature request header")
	ErrFailedToDecodeSignature     = errors.New("failed to decode signature")
)

type ErrIDNotWhitelisted struct {
	ID string
}

func (e ErrIDNotWhitelisted) Error() string {
	return fmt.Sprintf("provided Proxy-ID is not whitelisted: %s", e.ID)
}

type ErrSignatureInvalid struct{}

func (e ErrSignatureInvalid) Error() string {
	return "Request signature invalid"
}

type Authenticator interface {
	AuthenticateRequest(r *http.Request) error
}

type P2PAuthenticator struct {
	pubKeyMap map[string]p2pcrypto.PubKey
}

func NewP2PAuthenticator(allowedPubKeys []string) (*P2PAuthenticator, error) {
	pubKeys := map[string]p2pcrypto.PubKey{}

	for _, encodedPubKey := range allowedPubKeys {
		pubBytes, err := hex.DecodeString(encodedPubKey)
		if err != nil {
			return nil, err
		}

		pubKey, err := p2pcrypto.UnmarshalSecp256k1PublicKey(pubBytes)
		if err != nil {
			return nil, err
		}

		pubKeys[encodedPubKey] = pubKey
	}

	return &P2PAuthenticator{
		pubKeyMap: pubKeys,
	}, nil
}

// AuthenticateRequest checks the id of the forwarder and validates the
// signature
func (p *P2PAuthenticator) AuthenticateRequest(r *http.Request) error {
	id := r.Header.Get(ProxyIDHeader)
	if id == "" {
		return ErrMissingProxyIDHeader
	}

	pubKey, ok := p.pubKeyMap[id]
	if !ok {
		return &ErrIDNotWhitelisted{id}
	}
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return ErrFailedToReadRequestBody
	}
	// NOTE: this enables us to reread Body later if necessary
	r.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))

	signature := r.Header.Get(ProxySignatureHeader)
	if signature == "" {
		return ErrMissingSignatureFromRequest
	}
	decodedSignature, err := hex.DecodeString(signature)
	if err != nil {
		return ErrFailedToDecodeSignature
	}

	isValidSignature, err := pubKey.Verify(bodyBytes, decodedSignature)
	if err != nil {
		return fmt.Errorf("Signature verification failed: %s", err)
	}
	if !isValidSignature {
		return &ErrSignatureInvalid{}
	}

	return nil
}
