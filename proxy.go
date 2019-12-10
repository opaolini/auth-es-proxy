package main

import (
	"errors"
	"fmt"
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

var (
	ErrAllowedIDsNotUsed  = errors.New("AllowedIDs is set but not used with the selected authentication scheme")
	ErrUsersStringNotUsed = errors.New("AllowedBasicAuthUserString is set but not used with the selected authentication scheme")
)

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
		switch pc.SigningScheme {
		case BasicAuthScheme:
			signer, err := NewBasicAuthSigner(pc.BasicAuthUser, pc.BasicAuthPassword)
			if err != nil {
				return nil, err
			}

			proxy.signer = signer
		case EcdsaSignatureScheme:
			if pc.PrivateKeyPath == "" {
				return nil, errors.New("missing private key")
			}

			signer, err := NewP2PSignerFromKeyPath(pc.PrivateKeyPath)
			if err != nil {
				return nil, err
			}

			proxy.signer = signer
		case NoAuth:
			log.Warning("no signing method selected, yet ShouldSignOutgoing is set to true")
		default:
			log.Fatal("unknown signing scheme provided")

		}
	}

	if pc.ShouldValidateRequests {
		switch pc.AuthenticationScheme {
		case BasicAuthScheme:
			if pc.AllowedIDs != "" {
				return nil, ErrAllowedIDsNotUsed
			}

			authenticator, err := NewBasicAuthenticatorFromConfigString(pc.AllowedBasicAuthUserString)
			if err != nil {
				return nil, err
			}

			proxy.authenticator = authenticator
		case EcdsaSignatureScheme:
			if pc.AllowedBasicAuthUserString != "" {
				return nil, ErrUsersStringNotUsed
			}

			allowedPubKeys := strings.Split(pc.AllowedIDs, ",")
			authenticator, err := NewP2PAuthenticator(allowedPubKeys)
			if err != nil {
				return nil, err
			}

			proxy.authenticator = authenticator
		case NoAuth:
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

	log.Info("new proxy for ", targetURL)

	proxy.reverseProxy = newSingleHostReverseProxy(targetURL)

	return proxy, nil
}

// newSingleHostReverseProxy returns a new ReverseProxy that routes
// URLs to the scheme, host, and base path provided in target. If the
// target's path is "/base" and the incoming request was for "/dir",
// the target request will be for /base/dir.
// NewSingleHostReverseProxy does not rewrite the Host header.
// To rewrite Host headers, use ReverseProxy directly with a custom
// Director policy.
func newSingleHostReverseProxy(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}

		req.Host = target.Host // set Host header as expected by target
	}
	return &httputil.ReverseProxy{Director: director}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

type DebugTransport struct{}

func (DebugTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	b, err := httputil.DumpRequestOut(r, false)
	if err != nil {
		return nil, err
	}
	fmt.Println(string(b))
	return http.DefaultTransport.RoundTrip(r)
}
