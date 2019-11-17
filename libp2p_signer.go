package main

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"net/http"

	p2pcrypto "github.com/libp2p/go-libp2p-crypto"
)

// NewP2PSigner returns a new Signer which signs requests using libp2p-crypto
func NewP2PSigner(privKey p2pcrypto.PrivKey) (*P2PSigner, error) {
	publicKey := privKey.GetPublic()
	rawPubKey, err := publicKey.Raw()
	if err != nil {
		return nil, err
	}

	marshalledPubkey := hex.EncodeToString(rawPubKey)

	return &P2PSigner{
		privKey:          privKey,
		pubKey:           publicKey,
		marshalledPubKey: marshalledPubkey,
	}, nil

}

// NewP2PSignerFromKeyPath returns a new Signer which signs requests using
// libp2p-crypto with the private key loaded from file
func NewP2PSignerFromKeyPath(keyPath string) (*P2PSigner, error) {
	privKey, err := getPrivateKey(keyPath)
	if err != nil {
		return nil, err
	}

	return NewP2PSigner(privKey)
}

type P2PSigner struct {
	privKey p2pcrypto.PrivKey
	pubKey  p2pcrypto.PubKey

	// a b64 encoded pubKey, stringified
	marshalledPubKey string
}

func (p *P2PSigner) PubKey() string {
	return p.marshalledPubKey
}

func (p *P2PSigner) SignRequest(r *http.Request) error {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	// NOTE: this enables us to reread Body later if necessary
	r.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))

	signature, err := p.privKey.Sign(bodyBytes)
	if err != nil {
		return err
	}

	encodedSig := hex.EncodeToString(signature)

	r.Header.Set(ProxyIDHeader, p.marshalledPubKey)
	r.Header.Set(ProxySignatureHeader, encodedSig)

	return nil
}
