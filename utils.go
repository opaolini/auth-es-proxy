package main

import (
	"crypto/rand"
	"io/ioutil"

	p2pcrypto "github.com/libp2p/go-libp2p-crypto"
)

const ProxyIDHeader = "Proxy-ID"
const ProxySignatureHeader = "Proxy-Signature"

func getPrivateKey(path string) (p2pcrypto.PrivKey, error) {
	if path == "" {
		// If path is empty, generate a new key.
		priv, _, err := p2pcrypto.GenerateSecp256k1Key(rand.Reader)
		if err != nil {
			return nil, err
		}
		return priv, nil
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
