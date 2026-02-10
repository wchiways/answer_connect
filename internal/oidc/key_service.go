package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
)

var ErrPrivateKeyInvalid = errors.New("private key is invalid")

type JSONWebKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

type KeyService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	kid        string
}

func NewKeyService(privateKeyPEM string) (*KeyService, error) {
	key, err := parseOrGeneratePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	kid := computeKeyID(&key.PublicKey)
	return &KeyService{
		privateKey: key,
		publicKey:  &key.PublicKey,
		kid:        kid,
	}, nil
}

func (k *KeyService) PrivateKey() *rsa.PrivateKey {
	return k.privateKey
}

func (k *KeyService) PublicKey() *rsa.PublicKey {
	return k.publicKey
}

func (k *KeyService) KID() string {
	return k.kid
}

func (k *KeyService) JWKS() JSONWebKeySet {
	n := base64.RawURLEncoding.EncodeToString(k.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.publicKey.E)).Bytes())
	return JSONWebKeySet{
		Keys: []JSONWebKey{{
			Kty: "RSA",
			Use: "sig",
			Kid: k.kid,
			Alg: "RS256",
			N:   n,
			E:   e,
		}},
	}
}

func parseOrGeneratePrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	if privateKeyPEM == "" {
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, ErrPrivateKeyInvalid
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrPrivateKeyInvalid
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrPrivateKeyInvalid
	}
	return rsaKey, nil
}

func computeKeyID(publicKey *rsa.PublicKey) string {
	b := x509.MarshalPKCS1PublicKey(publicKey)
	s := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(s[:8])
}
