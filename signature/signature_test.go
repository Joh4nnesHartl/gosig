package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSerializeSignature(t *testing.T) {
	message := []byte("Hello ECDSA")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signature, err := CreateSignature(message, privateKey)
	require.NoError(t, err)

	base64signature := signature.Serialize()

	parsedSignature, err := ParseSignature(base64signature)
	require.NoError(t, err)

	assert.Equal(t, signature.R, parsedSignature.R)
	assert.Equal(t, signature.S, parsedSignature.S)

}

func TestVerifyValidSignature(t *testing.T) {
	message := []byte("Hello ECDSA")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signature, err := CreateSignature(message, privateKey)
	require.NoError(t, err)

	valid := VerifySignature(message, signature, &privateKey.PublicKey)

	assert.True(t, valid)
}

func TestVerifyInvalidSignature(t *testing.T) {
	message := []byte("Hello ECDSA")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signature, err := CreateSignature(message, privateKey)
	require.NoError(t, err)

	valid := VerifySignature([]byte("Bye ECDSA"), signature, &privateKey.PublicKey)

	assert.False(t, valid)
}
