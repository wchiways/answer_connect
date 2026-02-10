package oidc

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestIssueAndVerifyAccessToken(t *testing.T) {
	config := DefaultConfig()
	config.Issuer = "https://answer.example.com"
	ks, err := NewKeyService("")
	if err != nil {
		t.Fatalf("new key service: %v", err)
	}
	ts := NewTokenService(config, ks)

	token, _, err := ts.IssueAccessToken(AccessTokenClaims{
		Audience: "client-1",
		Subject:  "user-1",
		Scope:    []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	claims, err := ts.ParseAndValidateAccessToken(token)
	if err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Fatalf("unexpected subject: %v", claims["sub"])
	}
}

func TestIssueAndVerifyIDToken(t *testing.T) {
	config := DefaultConfig()
	config.Issuer = "https://answer.example.com"
	ks, err := NewKeyService("")
	if err != nil {
		t.Fatalf("new key service: %v", err)
	}
	ts := NewTokenService(config, ks)

	idToken, _, err := ts.IssueIDToken(IDTokenClaims{
		Audience: "client-1",
		Subject:  "user-1",
		Nonce:    "nonce-1",
		IssuedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("issue id token: %v", err)
	}
	parsed, err := jwt.ParseWithClaims(idToken, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return ks.PublicKey(), nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("parse id token: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("unexpected claims type: %T", parsed.Claims)
	}
	if claims["nonce"] != "nonce-1" {
		t.Fatalf("unexpected nonce: %v", claims["nonce"])
	}
}

func TestJWKSContainsActiveKey(t *testing.T) {
	ks, err := NewKeyService("")
	if err != nil {
		t.Fatalf("new key service: %v", err)
	}
	jwks := ks.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected single key in jwks, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != ks.KID() {
		t.Fatalf("unexpected kid, got %s want %s", jwks.Keys[0].Kid, ks.KID())
	}
}
