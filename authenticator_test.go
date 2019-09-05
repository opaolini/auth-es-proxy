package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthenticatorSetup(t *testing.T) {
	allowedIDs := []string{"036a775c4db73fd351191d0a0e19862ecbb70cbe2626097adfb70ffd4f9ea081bf"}
	_, err := NewP2PAuthenticator(allowedIDs)
	require.NoError(t, err)
}
