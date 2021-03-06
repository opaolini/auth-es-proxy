package main

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"net/http/httptest"
	"testing"

	p2pcrypto "github.com/libp2p/go-libp2p-crypto"
	"github.com/stretchr/testify/require"
)

const signerData = `
{"index":{"_index":"mesh_outside","_type":"docker"}}
{"@timestamp":"2019-06-30T11:07:15.000Z", "source":"stderr", "log":"{\"error\":\"Post http://ganache:8545: EOF\",\"level\":\"error\",\"msg\":\"BlockWatcher error encountered\",\"time\":\"2019-06-30T11:07:15Z\"}", "container_id":"b33055fd8054ad060d167da59798621a126093582e31c3c273ad2ddff928cc1b", "container_name":"/docker-compose-shipper_mesh_1"}
`

func TestSignAndAuth(t *testing.T) {
	signer, err := NewP2PSignerFromKeyPath("./__fixtures__/privkey")
	if err != nil {
		t.Fatal(err)
	}
	body := ioutil.NopCloser(bytes.NewReader([]byte(signerData)))
	request := httptest.NewRequest("POST", "/", body)

	err = signer.SignRequest(request)

	require.NoError(t, err)

	allowedIDs := []string{"036a775c4db73fd351191d0a0e19862ecbb70cbe2626097adfb70ffd4f9ea081bf"}
	auth, err := NewP2PAuthenticator(allowedIDs)

	require.NoError(t, err)

	err = auth.AuthenticateRequest(request)

	require.NoError(t, err, "did not properly authenticate the request with err: %s")
}

func TestLoadPrivateKey(t *testing.T) {
	expectedSignerPubKey := "036a775c4db73fd351191d0a0e19862ecbb70cbe2626097adfb70ffd4f9ea081bf"
	signer, err := NewP2PSignerFromKeyPath("./__fixtures__/privkey")

	require.NoError(t, err)

	require.Equalf(t, signer.PubKey(), expectedSignerPubKey, "invalid pubkey, expected %s instead got %s", expectedSignerPubKey, signer.PubKey())
}

func BenchmarkSigningData(b *testing.B) {
	b.StopTimer()
	privKey, _, err := p2pcrypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	signer, err := NewP2PSigner(privKey)
	if err != nil {
		b.Fatal(err)
	}

	body := ioutil.NopCloser(bytes.NewReader([]byte(signerData)))
	request := httptest.NewRequest("POST", "/", body)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		signer.SignRequest(request)
	}
}
