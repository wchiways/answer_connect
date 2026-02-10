package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var (
	ErrPKCEMethodNotSupported = errors.New("code_challenge_method must be S256")
	ErrPKCEVerifierMismatch   = errors.New("invalid code_verifier")
)

func verifyS256PKCE(codeVerifier, challenge string) error {
	if codeVerifier == "" || challenge == "" {
		return ErrPKCEVerifierMismatch
	}
	h := sha256.Sum256([]byte(codeVerifier))
	encoded := base64.RawURLEncoding.EncodeToString(h[:])
	if !constantTimeEquals(encoded, challenge) {
		return ErrPKCEVerifierMismatch
	}
	return nil
}
