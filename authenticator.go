package main

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"net/http"

	p2pcrypto "github.com/libp2p/go-libp2p-crypto"

	log "github.com/sirupsen/logrus"
)

type Authenticator interface {
	AuthenticateRequest(r *http.Request) bool
}

type P2PAuthenticator struct {
	// B64 encoded public keys of identities whose logs are allowed to be
	// ingested
	allowedPubKeys []string

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
		allowedPubKeys: allowedPubKeys,
		pubKeyMap:      pubKeys,
	}, nil
}

// AuthenticateRequest checks the id of the forwarder and validates the
// signature
// TODO: Return error for more specific validation errors?
func (p *P2PAuthenticator) AuthenticateRequest(r *http.Request) bool {
	id := r.Header.Get(ProxyIDHeader)
	if id == "" {
		log.Errorf("missing %s from headers", ProxyIDHeader)
		return false
	}

	pubKey, ok := p.pubKeyMap[id]
	if !ok {

		log.Errorf("id %s not on whitelist", id)
		return false
	}
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Error("failed to read body")
		return false
	}
	// NOTE: this enables us to reread Body later if necessary
	r.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))

	signature := r.Header.Get(ProxySignatureHeader)
	decodedSignature, err := hex.DecodeString(signature)
	if err != nil {
		log.Error("failed to decode signature")
		return false
	}

	keyOk, err := key.Verify(bodyBytes, decodedSignature)
	if !keyOk || err != nil {
		log.Errorf("failed to verify signature with err: %s", err)
		return false
	}

	return true
}
