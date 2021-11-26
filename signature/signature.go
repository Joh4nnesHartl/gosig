package signature

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

// Signature representates the signature pair (r,s)
type Signature struct {
	R, S *big.Int
}

// Serialize serializes the signature pair(r,s) => base64(r|s)
func (s Signature) Serialize() string {
	// append r & s => r|s
	signature := append(s.R.Bytes(), s.S.Bytes()...)

	return base64.StdEncoding.EncodeToString(signature)
}

// ParseSignature parses base64 encoded signature: base64(r|s)
func ParseSignature(signatureBase64 string) (Signature, error) {
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return Signature{}, err
	}

	return Signature{
		R: big.NewInt(0).SetBytes(signature[:len(signature)/2]),
		S: big.NewInt(0).SetBytes(signature[len(signature)/2:]),
	}, nil
}

// CreateSignature creates a signature over data with the provided private Key.
func CreateSignature(data []byte, privateKey *ecdsa.PrivateKey) (Signature, error) {
	// create hash over the data for the signing function
	hash := sha256.Sum256(data)

	// sign the data & retrieve (r,s)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return Signature{}, fmt.Errorf("error signing data: %s", err.Error())
	}

	return Signature{r, s}, nil
}

// VerifySignature verifies a signature made over data with the corresponding public key
func VerifySignature(data []byte, signature Signature, publicKey *ecdsa.PublicKey) bool {
	// create hash over the data for the verifying function
	hash := sha256.Sum256(data)

	return ecdsa.Verify(publicKey, hash[:], signature.R, signature.S)
}
