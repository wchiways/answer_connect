package oidc

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

type RevokeHandler struct {
	store Store
	nowFn func() time.Time
}

func NewRevokeHandler(store Store) *RevokeHandler {
	return &RevokeHandler{
		store: store,
		nowFn: func() time.Time { return time.Now().UTC() },
	}
}

func (h *RevokeHandler) Handle(ctx HTTPContext) {
	token := strings.TrimSpace(ctx.PostForm("token"))
	clientID := strings.TrimSpace(ctx.PostForm("client_id"))
	clientSecret := strings.TrimSpace(ctx.PostForm("client_secret"))
	if token == "" || clientID == "" {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_request", "token and client_id are required", "revoke")
		return
	}

	client, err := h.store.ValidateClientSecret(clientID, clientSecret)
	if err != nil {
		writeOAuthError(ctx, http.StatusUnauthorized, "invalid_client", "client credentials are invalid", "revoke")
		return
	}

	now := h.nowFn()
	record, err := h.store.GetRefreshToken(token, now)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenNotFound) || errors.Is(err, ErrRefreshTokenExpired) || errors.Is(err, ErrRefreshTokenRevoked) {
			ctx.Status(http.StatusOK)
			return
		}
		writeOAuthError(ctx, http.StatusInternalServerError, "server_error", "failed to revoke token", "revoke")
		return
	}
	if !constantTimeEquals(record.ClientID, client.ID) {
		ctx.Status(http.StatusOK)
		return
	}
	if err = h.store.RevokeRefreshToken(token, now); err != nil {
		writeOAuthError(ctx, http.StatusInternalServerError, "server_error", "failed to revoke token", "revoke")
		return
	}
	ctx.Status(http.StatusOK)
}
