package main

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Log forwarders like fluentd or fluentbit post log lines in bulk to this
// elasticsearch endpoint
const BulkLogsEndpoint = "/_bulk"

func unauthorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte("{\"message\":\"unauthorized\"}"))
}

type Proxy struct {
	config        *ProxyConfig
	httpClient    *http.Client
	remoteURL     *url.URL
	signer        Signer
	authenticator Authenticator
}

// isValidTargetEndpoint checks if the request is has a valid target depending
// on the configuration of the proxy
func (p *Proxy) isValidTargetEndpoint(r *http.Request) bool {
	if p.config.LogsOnly {
		if r.URL.Path != BulkLogsEndpoint {
			return false
		}
	}

	return true
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.isValidTargetEndpoint(r) {
		unauthorized(w)
		return
	}

	if p.config.InputValidation {
		ok := p.authenticator.AuthenticateRequest(r)
		if !ok {
			msg := "not authorized to proxy request"
			http.Error(w, msg, http.StatusUnauthorized)
			return
		}
	}

	if p.config.OutputSigning {
		err := p.signer.SignRequest(r)
		if err != nil {
			msg := "could not sign request"
			http.Error(w, msg, http.StatusInternalServerError)
			log.Error(err)
			return
		}
	}

	// RequestURI should not be set, otherwise http.Client witll throw an
	// error
	r.RequestURI = ""
	r.URL = p.remoteURL

	p.ProxyRequest(w, r)
}

func (p *Proxy) ProxyRequest(w http.ResponseWriter, r *http.Request) {
	resp, err := p.httpClient.Do(r)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		log.Error("ServeHTTP:", err)
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func NewProxy(pc *ProxyConfig) (*Proxy, error) {
	proxy := &Proxy{
		config:     pc,
		httpClient: &http.Client{},
	}

	if pc.OutputSigning {
		if pc.PrivateKeyPath == "" {
			return nil, errors.New("missing private key")
		}

		signer, err := NewP2PSignerFromKeyPath(pc.PrivateKeyPath)
		if err != nil {
			return nil, err
		}
		proxy.signer = signer
	}

	if pc.InputValidation {
		allowedPubKeys := strings.Split(pc.AllowedIDs, ",")
		authenticator, err := NewP2PAuthenticator(allowedPubKeys)
		if err != nil {
			return nil, err
		}

		proxy.authenticator = authenticator
	}

	targetURL, err := url.Parse(pc.RemoteAddress)
	if err != nil {
		return nil, err
	}

	proxy.remoteURL = targetURL

	return proxy, nil
}
