package main

import (
	"reflect"
	"testing"
)

func TestNewBasicAuthenticator(t *testing.T) {
	_, err := NewBasicAuthenticatorFromConfigString("user:password,becky:hello")
	if err != nil {
		t.Fatal(err)
	}
}

func Test_parseAllowedUsersString(t *testing.T) {
	type args struct {
		userString string
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]string
		wantErr bool
	}{
		{"simple valid test", args{"user:password"}, map[string]string{"user": "password"}, false},
		{
			"more than one valid test",
			args{"user:password,user2:password2"},
			map[string]string{"user": "password", "user2": "password2"},
			false,
		},
		{"should throw error test", args{"user/password"}, map[string]string{}, true},
		{"empty string test", args{""}, map[string]string{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAllowedUsersString(tt.args.userString)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAllowedUsersString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAllowedUsersString() = %v, want %v", got, tt.want)
			}
		})
	}
}
