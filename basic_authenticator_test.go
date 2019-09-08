package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBasicAuthenticator(t *testing.T) {
	_, err := NewBasicAuthenticatorFromConfigString("user:password,becky:hello")
	require.NoError(t, err)
}

func TestParseAllowedUsersString(t *testing.T) {
	type args struct {
		userString string
	}
	tests := []struct {
		name      string
		args      args
		expected  map[string]string
		expectErr bool
	}{
		{"simple valid test", args{"user:password"}, map[string]string{"user": "password"}, false},
		{
			"more than one valid test",
			args{"user:password,user2:password2"},
			map[string]string{"user": "password", "user2": "password2"},
			false,
		},
		{"should throw error test", args{"user/password"}, nil, true},
		{"empty string test", args{""}, nil, true},
		{"string contains only commas", args{"user1,user2,user3"}, nil, true},
		{"string contains only colons", args{"user1:user2:user3"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAllowedUsersString(tt.args.userString)
			if (err != nil) != tt.expectErr {
				t.Errorf("parseAllowedUsersString() error = %v, wantErr %v", err, tt.expectErr)
				return
			}
			assert.Equal(t, tt.expected, got)
		})
	}
}
