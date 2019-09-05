package main

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
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

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

type Proxy struct {
	config                 *ProxyConfig
	httpClient             *http.Client
	remoteURL              *url.URL
	allowedURLRegexPattern *regexp.Regexp
	signer                 Signer
	authenticator          Authenticator
	reverseProxy           *httputil.ReverseProxy
}

// isValidTargetEndpoint checks if the request has a valid target depending
// on the configuration of the proxy
func (p *Proxy) isValidTargetEndpoint(r *http.Request) bool {
	return p.allowedURLRegexPattern.MatchString(r.URL.Path)

}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.config.AllowedPathRegex != "" && !p.isValidTargetEndpoint(r) {
		unauthorized(w)
		return
	}

	if p.config.ShouldValidateRequests {
		err := p.authenticator.AuthenticateRequest(r)
		switch err.(type) {
		case nil:
			log.Trace("Authentication succesful")
		case ErrIDNotWhitelisted:
		case ErrSignatureInvalid:
			msg := "not authorized to proxy request"
			http.Error(w, msg, http.StatusUnauthorized)

			log.
				WithField("error", err).
				WithField("proxy-id", r.Header.Get(ProxyIDHeader)).
				Warning("AuthenticateRequest not authorized to proxy request")
			return
		default:
			http.Error(w, err.Error(), http.StatusBadRequest)
			log.WithField("error", err).Error("AuthenticateRequest returned an error")
			return
		}
	}

	if p.config.ShouldSignOutgoing {
		err := p.signer.SignRequest(r)
		if err != nil {
			msg := "could not sign request"
			http.Error(w, msg, http.StatusInternalServerError)
			log.Error(err)
			return
		}
	}

	p.ProxyRequest(w, r)
}

func (p *Proxy) ProxyRequest(w http.ResponseWriter, r *http.Request) {
	p.reverseProxy.ServeHTTP(w, r)
}

func NewProxy(pc *ProxyConfig) (*Proxy, error) {
	proxy := &Proxy{
		config:     pc,
		httpClient: &http.Client{},
	}

	if pc.ShouldSignOutgoing {
		if pc.PrivateKeyPath == "" {
			return nil, errors.New("missing private key")
		}

		signer, err := NewP2PSignerFromKeyPath(pc.PrivateKeyPath)
		if err != nil {
			return nil, err
		}
		proxy.signer = signer
	}

	if pc.ShouldValidateRequests {

		switch pc.AuthenticationScheme {
		case BASIC_AUTH_SCHEME:
			authenticator, err := NewBasicAuthenticatorFromConfigString(pc.AllowedBasicAuthUserString)
			if err != nil {
				return nil, err
			}

			proxy.authenticator = authenticator
		case ECDSA_SIGNATURE_SCHEME:
			allowedPubKeys := strings.Split(pc.AllowedIDs, ",")
			authenticator, err := NewP2PAuthenticator(allowedPubKeys)
			if err != nil {
				return nil, err
			}

			proxy.authenticator = authenticator
		case NO_AUTH:
			log.Warning("no authentication selected")
		default:
			log.Fatal("unknown authentication scheme provided")

		}

	}

	if pc.AllowedPathRegex != "" {
		proxy.allowedURLRegexPattern = regexp.MustCompile(pc.AllowedPathRegex)
	}

	targetURL, err := url.Parse(pc.RemoteAddress)
	if err != nil {
		return nil, err
	}

	proxy.reverseProxy = httputil.NewSingleHostReverseProxy(targetURL)

	return proxy, nil
}
