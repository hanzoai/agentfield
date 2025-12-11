package webhooks

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComputeAndValidateSignature(t *testing.T) {
	secret := "whs_secret"
	timestamp := "1702342800"
	body := []byte(`{"hello":"world"}`)

	sig, err := ComputeSignature(secret, timestamp, body)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(sig, "sha256="))

	require.True(t, ValidateSignature(secret, sig, timestamp, body))
	require.False(t, ValidateSignature(secret, "sha256=deadbeef", timestamp, body))
	require.False(t, ValidateSignature("", sig, timestamp, body))
	require.False(t, ValidateSignature(secret, sig, "", body))
}
