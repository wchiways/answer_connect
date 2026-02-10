package oidc

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

type TokenHandler struct {
	store        Store
	tokenService *TokenService
	nowFn        func() time.Time
}

func NewTokenHandler(store Store, tokenService *TokenService) *TokenHandler {
	return &TokenHandler{
		store:        store,
		tokenService: tokenService,
		nowFn:        func() time.Time { return time.Now().UTC() },
	}
}

func (h *TokenHandler) Handle(ctx HTTPContext) {
	grantType := strings.TrimSpace(ctx.PostForm("grant_type"))
	if grantType == "authorization_code" {
		h.handleAuthorizationCodeGrant(ctx)
		return
	}
	if grantType == "refresh_token" {
		h.handleRefreshGrant(ctx)
		return
	}
	writeOAuthError(ctx, http.StatusBadRequest, "unsupported_grant_type", "grant_type is not supported", "token")
}

func (h *TokenHandler) handleAuthorizationCodeGrant(ctx HTTPContext) {
	clientID := strings.TrimSpace(ctx.PostForm("client_id"))
	clientSecret := strings.TrimSpace(ctx.PostForm("client_secret"))
	code := strings.TrimSpace(ctx.PostForm("code"))
	redirectURI := strings.TrimSpace(ctx.PostForm("redirect_uri"))
	codeVerifier := strings.TrimSpace(ctx.PostForm("code_verifier"))

	if clientID == "" || code == "" || redirectURI == "" || codeVerifier == "" {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_request", "missing required parameters", "token")
		return
	}
	client, err := h.store.ValidateClientSecret(clientID, clientSecret)
	if err != nil {
		writeOAuthError(ctx, http.StatusUnauthorized, "invalid_client", "client credentials are invalid", "token")
		return
	}
	codeRecord, err := h.store.ConsumeAuthCode(code, h.nowFn())
	if err != nil {
		h.mapCodeError(ctx, err)
		return
	}
	if !constantTimeEquals(codeRecord.ClientID, client.ID) || !constantTimeEquals(codeRecord.RedirectURI, redirectURI) {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_grant", "authorization code does not match client or redirect_uri", "token")
		return
	}
	if err = verifyS256PKCE(codeVerifier, codeRecord.CodeChallenge); err != nil {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_grant", "code_verifier is invalid", "token")
		return
	}
	response, err := h.issueTokenResponse(client, codeRecord.UserID, codeRecord.Nonce, codeRecord.Scope)
	if err != nil {
		writeOAuthError(ctx, http.StatusInternalServerError, "server_error", "failed to issue tokens", "token")
		return
	}
	ctx.JSON(http.StatusOK, response)
}

func (h *TokenHandler) handleRefreshGrant(ctx HTTPContext) {
	clientID := strings.TrimSpace(ctx.PostForm("client_id"))
	clientSecret := strings.TrimSpace(ctx.PostForm("client_secret"))
	refreshToken := strings.TrimSpace(ctx.PostForm("refresh_token"))
	if clientID == "" || refreshToken == "" {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_request", "client_id and refresh_token are required", "token")
		return
	}
	client, err := h.store.ValidateClientSecret(clientID, clientSecret)
	if err != nil {
		writeOAuthError(ctx, http.StatusUnauthorized, "invalid_client", "client credentials are invalid", "token")
		return
	}
	now := h.nowFn()
	record, err := h.store.GetRefreshToken(refreshToken, now)
	if err != nil {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_grant", "refresh token is invalid", "token")
		return
	}
	if !constantTimeEquals(record.ClientID, client.ID) {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_grant", "refresh token does not belong to client", "token")
		return
	}
	response, newRecord, rawRefresh, err := h.issueRefreshedResponse(client, record.UserID, record.Scope)
	if err != nil {
		writeOAuthError(ctx, http.StatusInternalServerError, "server_error", "failed to issue refreshed tokens", "token")
		return
	}
	if err = h.store.RotateRefreshToken(refreshToken, newRecord, now); err != nil {
		if errors.Is(err, ErrRefreshTokenReplay) {
			writeOAuthError(ctx, http.StatusBadRequest, "invalid_grant", "refresh token replay detected", "token")
			return
		}
		writeOAuthError(ctx, http.StatusInternalServerError, "server_error", "failed to rotate refresh token", "token")
		return
	}
	response.RefreshToken = rawRefresh
	ctx.JSON(http.StatusOK, response)
}

func (h *TokenHandler) mapCodeError(ctx HTTPContext, err error) {
	if errors.Is(err, ErrAuthCodeNotFound) || errors.Is(err, ErrAuthCodeExpired) || errors.Is(err, ErrAuthCodeConsumed) {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_grant", "authorization code is invalid", "token")
		return
	}
	writeOAuthError(ctx, http.StatusInternalServerError, "server_error", "failed to consume authorization code", "token")
}

func (h *TokenHandler) issueTokenResponse(client OIDCClient, userID, nonce string, scopes []string) (TokenResponse, error) {
	accessToken, expiresIn, err := h.tokenService.IssueAccessToken(AccessTokenClaims{
		Audience: client.ID,
		Subject:  userID,
		Scope:    scopes,
	})
	if err != nil {
		return TokenResponse{}, err
	}
	idToken, _, err := h.tokenService.IssueIDToken(IDTokenClaims{
		Audience: client.ID,
		Subject:  userID,
		Nonce:    nonce,
	})
	if err != nil {
		return TokenResponse{}, err
	}
	rawRefresh, refreshHash, refreshExpiresAt, err := h.tokenService.NewRefreshToken()
	if err != nil {
		return TokenResponse{}, err
	}
	if err = h.store.SaveRefreshToken(RefreshTokenRecord{
		TokenHash: refreshHash,
		ClientID:  client.ID,
		UserID:    userID,
		Scope:     scopes,
		ExpiresAt: refreshExpiresAt,
		CreatedAt: h.nowFn(),
	}); err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: rawRefresh,
		IDToken:      idToken,
		Scope:        joinScope(scopes),
	}, nil
}

func (h *TokenHandler) issueRefreshedResponse(client OIDCClient, userID string, scopes []string) (TokenResponse, RefreshTokenRecord, string, error) {
	accessToken, expiresIn, err := h.tokenService.IssueAccessToken(AccessTokenClaims{
		Audience: client.ID,
		Subject:  userID,
		Scope:    scopes,
	})
	if err != nil {
		return TokenResponse{}, RefreshTokenRecord{}, "", err
	}
	rawRefresh, refreshHash, refreshExpiresAt, err := h.tokenService.NewRefreshToken()
	if err != nil {
		return TokenResponse{}, RefreshTokenRecord{}, "", err
	}
	newRecord := RefreshTokenRecord{
		TokenHash: refreshHash,
		ClientID:  client.ID,
		UserID:    userID,
		Scope:     scopes,
		ExpiresAt: refreshExpiresAt,
		CreatedAt: h.nowFn(),
	}
	return TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       joinScope(scopes),
	}, newRecord, rawRefresh, nil
}
