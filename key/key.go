package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateKeyPair generates an ECDSA public / private key pair
func GenerateKeyPair() (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating ecdsa key pair: %s", err.Error())
	}

	return &privateKey.PublicKey, privateKey, nil
}

// SerializePublicKey serializes the public key in PEM format
func SerializePublicKey(publicKey *ecdsa.PublicKey) ([]byte, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}

	return pem.EncodeToMemory(publicKeyBlock), nil
}

// SerializePrivateKeY serializes the private key in PEM format
func SerializePrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	privateKeyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyDER,
	}

	return pem.EncodeToMemory(privateKeyBlock), nil
}

// ParsePublicKey parses an public key serialized in PEM format
func ParsePublicKey(pubPEM []byte) (*ecdsa.PublicKey, error) {
	publicKeyBlock, _ := pem.Decode(pubPEM)

	pub, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing EC Public key: %s", err.Error())
	}

	// assert that the parsed public key is an EC public key
	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error parsing EC public key: must be *ecdsa.PublicKey, got: %T", pub)
	}

	return publicKey, nil
}

// ParsePrivateKey parses an private key serialized in PEM format
func ParsePrivatKey(privPEM []byte) (*ecdsa.PrivateKey, error) {
	privateKeyBlock, _ := pem.Decode(privPEM)

	return x509.ParseECPrivateKey(privateKeyBlock.Bytes)
}
