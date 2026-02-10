package oidc

import (
	"net/http"
	"strings"
)

type UserInfoResolver func(userID string) (UserProfile, error)

type UserInfoHandler struct {
	tokenService *TokenService
	resolveUser  UserInfoResolver
}

func NewUserInfoHandler(tokenService *TokenService, resolveUser UserInfoResolver) *UserInfoHandler {
	return &UserInfoHandler{
		tokenService: tokenService,
		resolveUser:  resolveUser,
	}
}

func (h *UserInfoHandler) Handle(ctx HTTPContext) {
	rawAuthorization := strings.TrimSpace(ctx.Header("Authorization"))
	if !strings.HasPrefix(strings.ToLower(rawAuthorization), "bearer ") {
		unauthorized(ctx, "userinfo")
		return
	}
	rawToken := strings.TrimSpace(rawAuthorization[len("Bearer "):])
	claims, err := h.tokenService.ParseAndValidateAccessToken(rawToken)
	if err != nil {
		unauthorized(ctx, "userinfo")
		return
	}
	userID, _ := claims["sub"].(string)
	if userID == "" {
		unauthorized(ctx, "userinfo")
		return
	}
	user, err := h.resolveUser(userID)
	if err != nil {
		unauthorized(ctx, "userinfo")
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"sub":                user.ID,
		"preferred_username": user.Username,
		"name":               user.Name,
		"email":              user.Email,
		"email_verified":     user.Email != "",
	})
}
