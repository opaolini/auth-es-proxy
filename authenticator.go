package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	p2pcrypto "github.com/libp2p/go-libp2p-crypto"

	log "github.com/sirupsen/logrus"
)

var (
	ErrMissingProxyIDHeader        = errors.New("missing Proxy-ID from request headers")
	ErrIdIsNotWhitelisted          = errors.New("provided Proxy-ID is whitelisted")
	ErrFailedToReadRequestBody     = errors.New("failed to read request body")
	ErrMissingSignatureFromRequest = errors.New("missing signature from request headers")
	ErrFailedToDecodeSignature     = errors.New("failed to decode signature")
)

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
		log.Errorf("missing %s from headers", ProxyIDHeader)
		return ErrMissingProxyIDHeader
	}

	pubKey, ok := p.pubKeyMap[id]
	if !ok {
		return ErrIdIsNotWhitelisted
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
		log.Error("failed to decode signature")
		return ErrFailedToDecodeSignature
	}

	keyOk, err := pubKey.Verify(bodyBytes, decodedSignature)
	if !keyOk || err != nil {
		return fmt.Errorf("failed to verify signature with err: %s", err)
	}

	return nil
}
