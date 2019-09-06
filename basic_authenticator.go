package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var (
	ErrInvalidUserOrPassword = errors.New("incorrect username or password")
	ErrFailedHttpBasicAuth   = errors.New("failed http basic auth, missing or malformed Authorization headers?")
)

// BasicAuthenticator uses HTTP Basic Auth to check whether the incoming request
// is allowed access.
type BasicAuthenticator struct {
	// mapping of user to password
	userToPassword map[string]string
}

func (a *BasicAuthenticator) AuthenticateRequest(r *http.Request) error {
	user, pass, ok := r.BasicAuth()

	if !ok {
		return ErrFailedHttpBasicAuth
	}

	password, userPresent := a.userToPassword[user]

	if !userPresent || password != pass {
		return ErrInvalidUserOrPassword
	}

	return nil
}

func NewBasicAuthenticator(userToPassword map[string]string) (*BasicAuthenticator, error) {
	if len(userToPassword) == 0 {
		return nil, errors.New("provided an empty userToPassword map")
	}
	return &BasicAuthenticator{
		userToPassword: userToPassword,
	}, nil
}

// parseAllowedUsersString is used to convert a user1:password1,user2:password2
// string into a mapping of users to passwords
func parseAllowedUsersString(userString string) (map[string]string, error) {
	if userString == "" {
		return nil, errors.New("empty userString provided")
	}

	userToPassword := map[string]string{}
	pairs := strings.Split(userString, ",")
	for _, pair := range pairs {
		userPassword := strings.Split(pair, ":")
		if len(userPassword) != 2 {
			return nil, fmt.Errorf("could not parse the following user pair: %s", pair)
		}

		user, password := strings.TrimSpace(userPassword[0]), strings.TrimSpace(userPassword[1])
		userToPassword[user] = password
	}
	return userToPassword, nil
}

func NewBasicAuthenticatorFromConfigString(allowedUserString string) (*BasicAuthenticator, error) {
	userToPassword, err := parseAllowedUsersString(allowedUserString)
	if err != nil {
		return nil, err
	}
	return NewBasicAuthenticator(userToPassword)
}
