package oidc

import (
	"encoding/json"
	"testing"
)

func TestCreateClient(t *testing.T) {
	handler := NewAdminClientHandler(NewInMemoryStore())
	ctx := &fakeContext{bindBody: mustMarshal(t, map[string]any{
		"name":          "Test Client",
		"redirect_uris": []string{"https://client.example.com/callback"},
		"scopes":        []string{"openid", "profile"},
		"grant_types":   []string{"authorization_code", "refresh_token"},
	})}

	handler.HandleCreate(ctx)
	if ctx.statusCode != 201 {
		t.Fatalf("expected 201, got %d body=%s", ctx.statusCode, mustJSON(ctx.jsonBody))
	}
	body, ok := ctx.jsonBody.(map[string]any)
	if !ok {
		t.Fatalf("unexpected body type: %T", ctx.jsonBody)
	}
	if body["client_secret"] == "" {
		t.Fatalf("expected client_secret in response")
	}
}

func TestListClients(t *testing.T) {
	store := NewInMemoryStore()
	handler := NewAdminClientHandler(store)
	if _, _, err := store.CreateClient(OIDCClient{Name: "Client 1", RedirectURIs: []string{"https://client.example.com/callback"}, Scopes: []string{"openid"}}, "secret"); err != nil {
		t.Fatalf("create client: %v", err)
	}

	ctx := &fakeContext{}
	handler.HandleList(ctx)
	if ctx.statusCode != 200 {
		t.Fatalf("expected 200, got %d", ctx.statusCode)
	}
	body, ok := ctx.jsonBody.(map[string]any)
	if !ok {
		t.Fatalf("unexpected body type: %T", ctx.jsonBody)
	}
	clients, ok := body["clients"].([]OIDCClient)
	if !ok {
		t.Fatalf("unexpected clients type: %T", body["clients"])
	}
	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(clients))
	}
}

func TestUpdateClient(t *testing.T) {
	store := NewInMemoryStore()
	handler := NewAdminClientHandler(store)
	client, _, err := store.CreateClient(OIDCClient{
		ID:           "client_1",
		Name:         "Client 1",
		RedirectURIs: []string{"https://client.example.com/callback"},
		Scopes:       []string{"openid"},
	}, "secret")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	ctx := &fakeContext{bindBody: mustMarshal(t, map[string]any{
		"name":          "Client 1 Updated",
		"redirect_uris": []string{"https://client.example.com/callback2"},
		"scopes":        []string{"openid", "profile"},
		"status":        "active",
	})}
	handler.HandleUpdate(ctx, client.ID)

	if ctx.statusCode != 200 {
		t.Fatalf("expected 200, got %d body=%s", ctx.statusCode, mustJSON(ctx.jsonBody))
	}
	updated, ok := ctx.jsonBody.(OIDCClient)
	if !ok {
		t.Fatalf("unexpected body type: %T", ctx.jsonBody)
	}
	if updated.Name != "Client 1 Updated" {
		t.Fatalf("unexpected updated name: %s", updated.Name)
	}
}

func TestDeleteClient(t *testing.T) {
	store := NewInMemoryStore()
	handler := NewAdminClientHandler(store)
	client, _, err := store.CreateClient(OIDCClient{
		ID:           "client_1",
		Name:         "Client 1",
		RedirectURIs: []string{"https://client.example.com/callback"},
		Scopes:       []string{"openid"},
	}, "secret")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	ctx := &fakeContext{}
	handler.HandleDelete(ctx, client.ID)
	if ctx.statusCode != 204 {
		t.Fatalf("expected 204, got %d", ctx.statusCode)
	}
	if _, err = store.GetClient(client.ID); err == nil {
		t.Fatalf("client should be deleted")
	}
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal test value: %v", err)
	}
	return b
}
