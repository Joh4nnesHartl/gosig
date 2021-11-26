package key

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSerializePublicKey(t *testing.T) {
	publicKey, _, err := GenerateKeyPair()
	require.NoError(t, err)

	pubASN1, err := SerializePublicKey(publicKey)
	require.NoError(t, err)

	parsedPublicKey, err := ParsePublicKey(pubASN1)
	require.NoError(t, err)

	assert.Equal(t, publicKey, parsedPublicKey)
}

func TestSerializePrivateKey(t *testing.T) {
	_, privateKey, err := GenerateKeyPair()
	require.NoError(t, err)

	privASN1, err := SerializePrivateKey(privateKey)
	require.NoError(t, err)

	parsedPrivateKey, err := ParsePrivatKey(privASN1)
	require.NoError(t, err)

	assert.Equal(t, privateKey, parsedPrivateKey)
}
