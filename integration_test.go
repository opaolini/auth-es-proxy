package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"testing"
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

	ctx := context.TODO()

	payload := fmt.Sprintf("{%q:%q}", "hello", "world")
	payloadBytes := []byte(payload)

	go es.Start()

	proxyConfig := ProxyConfig{
		RemoteAddress:   "http://localhost:3010/",
		InputValidation: false,
	}
	proxy, err := NewProxy(&proxyConfig)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		t.Log(http.ListenAndServe("localhost:3011", proxy))
	}()

	resp, err := tc.SendPOST("http://localhost:3011/", payloadBytes)
	if err != nil {
		t.Fatal(err)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("could not read body with err: %s", err)
	}

	if !bytes.Equal(bodyBytes, payloadBytes) {
		t.Fatalf("the body does not the expected payload, received: %s , expected: %s", bodyBytes, payloadBytes)
	}

	headerValue := resp.Header.Get(TestHeaderKey)

	if headerValue != TestHeaderValue {
		t.Fatalf("the expected value for %s header is %s instead got %s", TestHeaderKey, TestHeaderValue, headerValue)
	}

	es.Stop(ctx)

}

func TestAllowedRegexpProxy(t *testing.T) {
	tc := newTestClient()
	es := newEchoServer("localhost:3010")

	ctx := context.TODO()

	payload := fmt.Sprintf("{%q:%q}", "hello", "world")
	payloadBytes := []byte(payload)

	go es.Start()

	proxyConfig := ProxyConfig{
		RemoteAddress:    "http://localhost:3010/",
		InputValidation:  false,
		AllowedPathRegex: "/$",
	}
	proxy, err := NewProxy(&proxyConfig)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		t.Log(http.ListenAndServe("localhost:3011", proxy))
	}()

	resp, err := tc.SendPOST("http://localhost:3011/unallowed/path", payloadBytes)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode == 200 {
		t.Fatal("expected status code to not be 200")
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("could not read body with err: %s", err)
	}

	unauthorizedString := fmt.Sprintf("{%q:%q}", "message", "unauthorized")
	if !bytes.Equal(bodyBytes, []byte(unauthorizedString)) {
		t.Fatalf("the body does not the expected payload, received: %s , expected: %s", bodyBytes, payloadBytes)
	}

	es.Stop(ctx)
}
