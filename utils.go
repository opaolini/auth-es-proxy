package main

import (
	"errors"
	"io/ioutil"

	p2pcrypto "github.com/libp2p/go-libp2p-crypto"
)

const ProxyIDHeader = "Proxy-ID"
const ProxySignatureHeader = "Proxy-Signature"

var ErrEmptyPrivateKeyPath = errors.New("empty path to private key provided, a valid path is necessary")

func getPrivateKey(path string) (p2pcrypto.PrivKey, error) {
	if path == "" {
		return nil, ErrEmptyPrivateKeyPath
	}

	// Otherwise parse the key at the path given.
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decodedKey, err := p2pcrypto.ConfigDecodeKey(string(keyBytes))
	if err != nil {
		return nil, err
	}
	priv, err := p2pcrypto.UnmarshalPrivateKey(decodedKey)
	if err != nil {
		return nil, err
	}
	return priv, nil
}
