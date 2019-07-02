package main

import (
	"errors"
	"net/http"
	"net/http/httputil"
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
	httpProxy     *httputil.ReverseProxy
	remoteURL     *url.URL
	signer        Signer
	authenticator Authenticator
}

// isValidTargetEndpoint checks if the request has a valid target depending
// on the configuration of the proxy
func (p *Proxy) isValidTargetEndpoint(r *http.Request) bool {
	return r.URL.Path == BulkLogsEndpoint

}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.isValidTargetEndpoint(r) {
		unauthorized(w)
		return
	}

	if p.config.InputValidation {
		err := p.authenticator.AuthenticateRequest(r)
		switch err.(type) {
		case ErrIDNotWhitelisted:
		case ErrSignatureInvalid:
			msg := "not authorized to proxy request"
			http.Error(w, msg, http.StatusUnauthorized)
		default:
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		log.WithField("error", err).Error("AuthenticateRequest returned an error")
		return
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

	p.httpProxy.ServeHTTP(w, r)
}

func NewProxy(pc *ProxyConfig) (*Proxy, error) {
	targetURL, err := url.Parse(pc.RemoteAddress)
	if err != nil {
		return nil, err
	}

	proxy := &Proxy{
		config:    pc,
		httpProxy: httputil.NewSingleHostReverseProxy(targetURL),
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

	return proxy, nil
}
