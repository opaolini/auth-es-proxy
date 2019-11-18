package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

const TestHeaderKey = "X-Test-Header"
const TestHeaderValue = "test-value"

type testClient struct {
	httpClient *http.Client
}

func (c *testClient) send(method, url string, payload []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))

	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *testClient) SendPOST(url string, data []byte) (*http.Response, error) {
	return c.send("POST", url, data)
}

func newTestClient() *testClient {
	c := &http.Client{}
	return &testClient{
		httpClient: c,
	}
}

type echoServer struct {
	server *http.Server
}

func (e *echoServer) Start() error {
	return e.server.ListenAndServe()
}

func (e *echoServer) Stop(ctx context.Context) error {
	return e.server.Shutdown(ctx)
}

func newEchoServer(listenString string) *echoServer {
	m := http.NewServeMux()
	server := &http.Server{
		Addr:    listenString,
		Handler: m,
	}
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := ioutil.ReadAll(r.Body)

		fmt.Println("received request with the following body: ", string(bodyBytes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}

		w.Header().Add(TestHeaderKey, TestHeaderValue)

		io.Copy(w, bytes.NewBuffer(bodyBytes))
	})

	return &echoServer{server}
}

func TestBasicSingleProxySetup(t *testing.T) {
	tc := newTestClient()
	es := newEchoServer("localhost:3010")

	ctx := context.Background()

	payload := fmt.Sprintf("{%q:%q}", "hello", "world")
	payloadBytes := []byte(payload)

	go es.Start()

	proxyConfig := ProxyConfig{
		RemoteAddress:          "http://localhost:3010/",
		ShouldValidateRequests: false,
	}
	proxy, err := NewProxy(&proxyConfig)

	require.NoError(t, err)

	go func() {
		t.Log(http.ListenAndServe("localhost:3012", proxy))
	}()

	resp, err := tc.SendPOST("http://localhost:3012/", payloadBytes)

	require.NoError(t, err)

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	require.NoError(t, err, "could not read body")

	require.Truef(t, bytes.Equal(bodyBytes, payloadBytes), "the body does not have the expected payload, received: %s , expected: %s", bodyBytes, payloadBytes)

	headerValue := resp.Header.Get(TestHeaderKey)

	require.Equalf(t, headerValue, TestHeaderValue, "the expected value for %s header is %s instead got %s", TestHeaderKey, TestHeaderValue, headerValue)

	// TODO(oskar) - gracefully stop proxy by the end of the test
	es.Stop(ctx)
}

func TestAllowedRegexpProxy(t *testing.T) {
	tc := newTestClient()
	es := newEchoServer("localhost:3010")

	ctx := context.TODO()

	go es.Start()

	proxyConfig := ProxyConfig{
		RemoteAddress:          "http://localhost:3010/",
		ShouldValidateRequests: false,
		AllowedPathRegex:       "/$",
	}
	proxy, err := NewProxy(&proxyConfig)

	require.NoError(t, err)

	go func() {
		t.Log(http.ListenAndServe("localhost:3011", proxy))
	}()

	payload := fmt.Sprintf("{%q:%q}", "hello", "world")
	payloadBytes := []byte(payload)

	resp, err := tc.SendPOST("http://localhost:3011/disallowed/path", payloadBytes)

	require.NoError(t, err)

	require.NotEqual(t, 200, resp.StatusCode, "expected status code to not be 200")

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	require.NoError(t, err, "could not read body with err")

	unauthorizedString := fmt.Sprintf("{%q:%q}", "message", "unauthorized")

	require.Truef(t, bytes.Equal(bodyBytes, []byte(unauthorizedString)), "the body does not the expected payload, received: %s , expected: %s", bodyBytes, payloadBytes)

	// TODO(oskar) - gracefully stop proxy by the end of the test
	es.Stop(ctx)
}

func TestBasicAuthRoundtrip(t *testing.T) {
	tc := newTestClient()

	echoServerAddr := "localhost:3010"
	es := newEchoServer(echoServerAddr)

	ctx := context.Background()

	payload := fmt.Sprintf("{%q:%q}", "hello", "world")
	payloadBytes := []byte(payload)

	go es.Start()

	// Authentication Proxy setup
	username := "username"
	password := "password"

	authProxyConfig := ProxyConfig{
		RemoteAddress:              "http://" + echoServerAddr,
		ShouldValidateRequests:     true,
		AuthenticationScheme:       BasicAuthScheme,
		AllowedBasicAuthUserString: fmt.Sprintf("%s:%s", username, password),
	}
	authProxyAddr := "localhost:3012"

	proxy, err := NewProxy(&authProxyConfig)
	require.NoError(t, err)

	go func() {
		t.Log(http.ListenAndServe(authProxyAddr, proxy))
	}()

	// Signign Proxy Setup
	signingProxyConfig := ProxyConfig{
		RemoteAddress:      "http://" + authProxyAddr,
		ShouldSignOutgoing: true,
		SigningScheme:      BasicAuthScheme,
		BasicAuthUser:      username,
		BasicAuthPassword:  password,
	}
	signingProxyAddr := "localhost:3013"

	signingProxy, err := NewProxy(&signingProxyConfig)

	require.NoError(t, err)

	go func() {
		t.Log(http.ListenAndServe(signingProxyAddr, signingProxy))
	}()

	// Test Request
	resp, err := tc.SendPOST("http://"+signingProxyAddr, payloadBytes)
	require.NoError(t, err)

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err, "could not read body")
	require.Truef(t, bytes.Equal(bodyBytes, payloadBytes), "the body does not have the expected payload, received: %s , expected: %s", bodyBytes, payloadBytes)

	headerValue := resp.Header.Get(TestHeaderKey)
	require.Equalf(t, headerValue, TestHeaderValue, "the expected value for %s header is %s instead got %s", TestHeaderKey, TestHeaderValue, headerValue)

	es.Stop(ctx)
}
