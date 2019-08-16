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
	allowedUsers map[string]string
}

func (a *BasicAuthenticator) AuthenticateRequest(r *http.Request) error {
	user, pass, ok := r.BasicAuth()

	if !ok {
		return ErrFailedHttpBasicAuth
	}

	password, userPresent := a.allowedUsers[user]

	if !userPresent || password != pass {
		return ErrInvalidUserOrPassword
	}

	return nil
}

func NewBasicAuthenticator(allowedUsers map[string]string) (*BasicAuthenticator, error) {
	if len(allowedUsers) == 0 {
		return nil, errors.New("provided an empty allowedUsers map")
	}
	return &BasicAuthenticator{
		allowedUsers: allowedUsers,
	}, nil
}

// parseAllowedUsesrString is used to convert a user1:password1,user2:password2
// string into a mapping of users to passwords
func parseAllowedUsersString(userString string) (map[string]string, error) {
	if userString == "" {
		return map[string]string{}, fmt.Errorf("empty userString provided")
	}

	allowedUsers := map[string]string{}
	pairs := strings.Split(userString, ",")
	for _, pair := range pairs {
		userPassword := strings.Split(pair, ":")
		if len(userPassword) != 2 {
			return map[string]string{}, fmt.Errorf("could not parse the following user pair: %s", pair)
		}

		user, password := strings.TrimSpace(userPassword[0]), strings.TrimSpace(userPassword[1])
		allowedUsers[user] = password
	}
	return allowedUsers, nil
}

func NewBasicAuthenticatorFromConfigString(allowedUserString string) (*BasicAuthenticator, error) {
	allowedUsers, err := parseAllowedUsersString(allowedUserString)
	if err != nil {
		return nil, err
	}
	return NewBasicAuthenticator(allowedUsers)
}
