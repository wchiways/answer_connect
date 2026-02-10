package oidc

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuthorizeReturnsCodeWhenPKCEValid(t *testing.T) {
	store := NewInMemoryStore()
	_, _, err := store.CreateClient(OIDCClient{
		ID:           "client_1",
		Name:         "client-1",
		RedirectURIs: []string{"https://client.example.com/callback"},
		Scopes:       []string{"openid", "profile"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Status:       "active",
	}, "secret_1")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	handler := NewAuthorizeHandler(store, DefaultConfig(), func(_ HTTPContext) (UserProfile, error) {
		return UserProfile{ID: "u_1"}, nil
	})
	ctx := &fakeContext{
		query: map[string]string{
			"response_type":         "code",
			"client_id":             "client_1",
			"redirect_uri":          "https://client.example.com/callback",
			"scope":                 "openid profile",
			"state":                 "state-1",
			"nonce":                 "nonce-1",
			"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			"code_challenge_method": "S256",
		},
	}
	handler.Handle(ctx)

	if ctx.statusCode != 302 {
		t.Fatalf("expected redirect status 302, got %d", ctx.statusCode)
	}
	u, err := url.Parse(ctx.redirect)
	if err != nil {
		t.Fatalf("parse redirect uri: %v", err)
	}
	if code := u.Query().Get("code"); code == "" {
		t.Fatalf("redirect missing code: %s", ctx.redirect)
	}
	if state := u.Query().Get("state"); state != "state-1" {
		t.Fatalf("unexpected state: %s", state)
	}
}

func TestTokenExchangeSucceedsWithVerifier(t *testing.T) {
	store := NewInMemoryStore()
	_, _, err := store.CreateClient(OIDCClient{
		ID:                      "client_1",
		Name:                    "client-1",
		RedirectURIs:            []string{"https://client.example.com/callback"},
		Scopes:                  []string{"openid", "profile"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "client_secret_post",
		Status:                  "active",
	}, "secret_1")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	rawCode := "auth_code_1"
	err = store.SaveAuthCode(AuthCodeRecord{
		CodeHash:      sha256Hex(rawCode),
		ClientID:      "client_1",
		UserID:        "u_1",
		RedirectURI:   "https://client.example.com/callback",
		Scope:         []string{"openid", "profile"},
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeMethod:    "S256",
		ExpiresAt:     time.Now().UTC().Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("save auth code: %v", err)
	}

	ks, err := NewKeyService("")
	if err != nil {
		t.Fatalf("new key service: %v", err)
	}
	config := DefaultConfig()
	config.Issuer = "https://answer.example.com"
	handler := NewTokenHandler(store, NewTokenService(config, ks))
	ctx := &fakeContext{
		form: map[string]string{
			"grant_type":    "authorization_code",
			"client_id":     "client_1",
			"client_secret": "secret_1",
			"code":          rawCode,
			"redirect_uri":  "https://client.example.com/callback",
			"code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
	}
	handler.Handle(ctx)

	if ctx.statusCode != 200 {
		t.Fatalf("expected 200, got %d body=%s", ctx.statusCode, mustJSON(ctx.jsonBody))
	}
	response, ok := ctx.jsonBody.(TokenResponse)
	if !ok {
		t.Fatalf("expected token response, got %T", ctx.jsonBody)
	}
	if response.AccessToken == "" || response.IDToken == "" || response.RefreshToken == "" {
		t.Fatalf("missing tokens in response: %+v", response)
	}
}

func TestTokenExchangeFailsOnCodeReplay(t *testing.T) {
	store := NewInMemoryStore()
	client, _, err := store.CreateClient(OIDCClient{
		ID:                      "client_1",
		Name:                    "client-1",
		RedirectURIs:            []string{"https://client.example.com/callback"},
		Scopes:                  []string{"openid", "profile"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "client_secret_post",
		Status:                  "active",
	}, "secret_1")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	rawCode := "auth_code_1"
	now := time.Now().UTC()
	err = store.SaveAuthCode(AuthCodeRecord{
		CodeHash:      sha256Hex(rawCode),
		ClientID:      client.ID,
		UserID:        "u_1",
		RedirectURI:   "https://client.example.com/callback",
		Scope:         []string{"openid", "profile"},
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeMethod:    "S256",
		ExpiresAt:     now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("save auth code: %v", err)
	}
	if _, err = store.ConsumeAuthCode(rawCode, now); err != nil {
		t.Fatalf("first consume should pass: %v", err)
	}

	ks, err := NewKeyService("")
	if err != nil {
		t.Fatalf("new key service: %v", err)
	}
	config := DefaultConfig()
	config.Issuer = "https://answer.example.com"
	handler := NewTokenHandler(store, NewTokenService(config, ks))
	ctx := &fakeContext{form: map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     "client_1",
		"client_secret": "secret_1",
		"code":          rawCode,
		"redirect_uri":  "https://client.example.com/callback",
		"code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	}}
	handler.Handle(ctx)

	if ctx.statusCode != 400 {
		t.Fatalf("expected 400 on replay, got %d", ctx.statusCode)
	}
	payload := mustOAuthError(ctx.jsonBody)
	if payload.Error != "invalid_grant" {
		t.Fatalf("expected invalid_grant, got %s", payload.Error)
	}
}

func TestRefreshTokenFlowRotatesToken(t *testing.T) {
	store := NewInMemoryStore()
	_, _, err := store.CreateClient(OIDCClient{
		ID:                      "client_1",
		Name:                    "client-1",
		RedirectURIs:            []string{"https://client.example.com/callback"},
		Scopes:                  []string{"openid", "profile"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "client_secret_post",
		Status:                  "active",
	}, "secret_1")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	oldRefresh := "refresh_old"
	err = store.SaveRefreshToken(RefreshTokenRecord{
		TokenHash: sha256Hex(oldRefresh),
		ClientID:  "client_1",
		UserID:    "u_1",
		Scope:     []string{"openid", "profile"},
		ExpiresAt: time.Now().UTC().Add(2 * time.Hour),
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("save refresh token: %v", err)
	}

	ks, err := NewKeyService("")
	if err != nil {
		t.Fatalf("new key service: %v", err)
	}
	config := DefaultConfig()
	config.Issuer = "https://answer.example.com"
	handler := NewTokenHandler(store, NewTokenService(config, ks))
	ctx := &fakeContext{form: map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     "client_1",
		"client_secret": "secret_1",
		"refresh_token": oldRefresh,
	}}
	handler.Handle(ctx)

	if ctx.statusCode != 200 {
		t.Fatalf("expected 200, got %d body=%s", ctx.statusCode, mustJSON(ctx.jsonBody))
	}
	response, ok := ctx.jsonBody.(TokenResponse)
	if !ok {
		t.Fatalf("expected token response, got %T", ctx.jsonBody)
	}
	if response.RefreshToken == "" || strings.EqualFold(response.RefreshToken, oldRefresh) {
		t.Fatalf("expected rotated refresh token, got %q", response.RefreshToken)
	}
	if _, err = store.GetRefreshToken(oldRefresh, time.Now().UTC()); err == nil {
		t.Fatalf("old refresh token should be revoked")
	}
}

func TestAuthorizeSavesConsent(t *testing.T) {
	store := NewInMemoryStore()
	_, _, err := store.CreateClient(OIDCClient{
		ID:           "client_1",
		Name:         "client-1",
		RedirectURIs: []string{"https://client.example.com/callback"},
		Scopes:       []string{"openid", "profile"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Status:       "active",
	}, "secret_1")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	handler := NewAuthorizeHandler(store, DefaultConfig(), func(_ HTTPContext) (UserProfile, error) {
		return UserProfile{ID: "u_1"}, nil
	})
	ctx := &fakeContext{query: map[string]string{
		"response_type":         "code",
		"client_id":             "client_1",
		"redirect_uri":          "https://client.example.com/callback",
		"scope":                 "openid profile",
		"state":                 "state-1",
		"nonce":                 "nonce-1",
		"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"code_challenge_method": "S256",
	}}
	handler.Handle(ctx)

	if _, err = store.GetConsent("client_1", "u_1"); err != nil {
		t.Fatalf("consent should be saved: %v", err)
	}
}
