package oidc

import (
	"testing"
	"time"
)

func TestDiscoveryDocument(t *testing.T) {
	config := DefaultConfig()
	config.Issuer = "https://answer.example.com"
	config.BasePath = "/api/auth/oidc"
	ks, err := NewKeyService("")
	if err != nil {
		t.Fatalf("new key service: %v", err)
	}
	handler := NewMetadataHandler(config, ks)
	ctx := &fakeContext{}
	handler.HandleDiscovery(ctx)

	if ctx.statusCode != 200 {
		t.Fatalf("expected 200, got %d", ctx.statusCode)
	}
	body, ok := ctx.jsonBody.(map[string]any)
	if !ok {
		t.Fatalf("unexpected body type: %T", ctx.jsonBody)
	}
	if body["issuer"] != config.Issuer {
		t.Fatalf("issuer mismatch: %v", body["issuer"])
	}
	if body["authorization_endpoint"] == "" {
		t.Fatalf("missing authorization_endpoint")
	}
}

func TestUserInfoWithBearerToken(t *testing.T) {
	config := DefaultConfig()
	config.Issuer = "https://answer.example.com"
	ks, err := NewKeyService("")
	if err != nil {
		t.Fatalf("new key service: %v", err)
	}
	ts := NewTokenService(config, ks)
	accessToken, _, err := ts.IssueAccessToken(AccessTokenClaims{
		Audience:  "client_1",
		Subject:   "u_1",
		Scope:     []string{"openid", "profile"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	handler := NewUserInfoHandler(ts, func(userID string) (UserProfile, error) {
		return UserProfile{
			ID:       userID,
			Username: "user",
			Email:    "user@example.com",
			Name:     "User One",
		}, nil
	})
	ctx := &fakeContext{headers: map[string]string{"Authorization": "Bearer " + accessToken}}
	handler.Handle(ctx)

	if ctx.statusCode != 200 {
		t.Fatalf("expected 200, got %d body=%s", ctx.statusCode, mustJSON(ctx.jsonBody))
	}
	body, ok := ctx.jsonBody.(map[string]any)
	if !ok {
		t.Fatalf("unexpected body type: %T", ctx.jsonBody)
	}
	if body["sub"] != "u_1" {
		t.Fatalf("unexpected sub: %v", body["sub"])
	}
}

func TestRevokeRefreshToken(t *testing.T) {
	store := NewInMemoryStore()
	_, _, err := store.CreateClient(OIDCClient{
		ID:                      "client_1",
		Name:                    "client-1",
		RedirectURIs:            []string{"https://client.example.com/callback"},
		Scopes:                  []string{"openid"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "client_secret_post",
		Status:                  "active",
	}, "secret_1")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	rawToken := "refresh_token_1"
	err = store.SaveRefreshToken(RefreshTokenRecord{
		TokenHash: sha256Hex(rawToken),
		ClientID:  "client_1",
		UserID:    "u_1",
		Scope:     []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("save refresh token: %v", err)
	}

	handler := NewRevokeHandler(store)
	ctx := &fakeContext{form: map[string]string{
		"token":         rawToken,
		"client_id":     "client_1",
		"client_secret": "secret_1",
	}}
	handler.Handle(ctx)

	if ctx.statusCode != 200 {
		t.Fatalf("expected 200, got %d", ctx.statusCode)
	}
	if _, err = store.GetRefreshToken(rawToken, time.Now().UTC()); err == nil {
		t.Fatalf("token should be revoked")
	}
}
