package oidc

import (
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
	if token == "" {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_request", "token is required", "revoke")
		return
	}
	if err := h.store.RevokeRefreshToken(token, h.nowFn()); err != nil {
		writeOAuthError(ctx, http.StatusInternalServerError, "server_error", "failed to revoke token", "revoke")
		return
	}
	ctx.Status(http.StatusOK)
}
