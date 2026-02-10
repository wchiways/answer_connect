package oidc

import (
	"net/http"
	"strings"
)

type AdminClientHandler struct {
	store Store
}

func NewAdminClientHandler(store Store) *AdminClientHandler {
	return &AdminClientHandler{store: store}
}

type createClientRequest struct {
	ID                      string   `json:"id"`
	Name                    string   `json:"name"`
	RedirectURIs            []string `json:"redirect_uris"`
	Scopes                  []string `json:"scopes"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	FirstParty              bool     `json:"first_party"`
	Secret                  string   `json:"secret"`
}

type updateClientRequest struct {
	Name                    string   `json:"name"`
	RedirectURIs            []string `json:"redirect_uris"`
	Scopes                  []string `json:"scopes"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	FirstParty              bool     `json:"first_party"`
	Status                  string   `json:"status"`
}

func (h *AdminClientHandler) HandleCreate(ctx HTTPContext) {
	var req createClientRequest
	if err := ctx.BindJSON(&req); err != nil {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_request", "invalid request body", "admin_client_create")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_request", "name is required", "admin_client_create")
		return
	}
	client, secret, err := h.store.CreateClient(OIDCClient{
		ID:                      req.ID,
		Name:                    strings.TrimSpace(req.Name),
		RedirectURIs:            req.RedirectURIs,
		Scopes:                  req.Scopes,
		GrantTypes:              req.GrantTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		FirstParty:              req.FirstParty,
		Status:                  "active",
	}, req.Secret)
	if err != nil {
		if err == ErrClientExists {
			writeOAuthError(ctx, http.StatusConflict, "invalid_request", err.Error(), "admin_client_create")
			return
		}
		writeOAuthError(ctx, http.StatusInternalServerError, "server_error", "failed to create client", "admin_client_create")
		return
	}
	ctx.JSON(http.StatusCreated, map[string]any{
		"client":        client,
		"client_secret": secret,
	})
}

func (h *AdminClientHandler) HandleList(ctx HTTPContext) {
	ctx.JSON(http.StatusOK, map[string]any{"clients": h.store.ListClients()})
}

func (h *AdminClientHandler) HandleGet(ctx HTTPContext, clientID string) {
	client, err := h.store.GetClient(clientID)
	if err != nil {
		writeOAuthError(ctx, http.StatusNotFound, "invalid_request", ErrClientNotFound.Error(), "admin_client_get")
		return
	}
	ctx.JSON(http.StatusOK, client)
}

func (h *AdminClientHandler) HandleUpdate(ctx HTTPContext, clientID string) {
	var req updateClientRequest
	if err := ctx.BindJSON(&req); err != nil {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_request", "invalid request body", "admin_client_update")
		return
	}
	updated, err := h.store.UpdateClient(OIDCClient{
		ID:                      clientID,
		Name:                    strings.TrimSpace(req.Name),
		RedirectURIs:            req.RedirectURIs,
		Scopes:                  req.Scopes,
		GrantTypes:              req.GrantTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		FirstParty:              req.FirstParty,
		Status:                  req.Status,
	})
	if err != nil {
		if err == ErrClientNotFound {
			writeOAuthError(ctx, http.StatusNotFound, "invalid_request", err.Error(), "admin_client_update")
			return
		}
		writeOAuthError(ctx, http.StatusInternalServerError, "server_error", "failed to update client", "admin_client_update")
		return
	}
	ctx.JSON(http.StatusOK, updated)
}

func (h *AdminClientHandler) HandleDelete(ctx HTTPContext, clientID string) {
	if err := h.store.DeleteClient(clientID); err != nil {
		if err == ErrClientNotFound {
			writeOAuthError(ctx, http.StatusNotFound, "invalid_request", err.Error(), "admin_client_delete")
			return
		}
		writeOAuthError(ctx, http.StatusInternalServerError, "server_error", "failed to delete client", "admin_client_delete")
		return
	}
	ctx.Status(http.StatusNoContent)
}
