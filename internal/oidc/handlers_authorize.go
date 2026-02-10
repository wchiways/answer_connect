package oidc

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type UserResolver func(ctx HTTPContext) (UserProfile, error)

type AuthorizeHandler struct {
	store            Store
	config           Config
	nowFn            func() time.Time
	resolveLoginUser UserResolver
}

func NewAuthorizeHandler(store Store, config Config, resolve UserResolver) *AuthorizeHandler {
	return &AuthorizeHandler{
		store:            store,
		config:           config.normalize(),
		nowFn:            func() time.Time { return time.Now().UTC() },
		resolveLoginUser: resolve,
	}
}

func (h *AuthorizeHandler) Handle(ctx HTTPContext) {
	responseType := ctx.Query("response_type")
	clientID := strings.TrimSpace(ctx.Query("client_id"))
	redirectURI := strings.TrimSpace(ctx.Query("redirect_uri"))
	scope := splitScope(ctx.Query("scope"))
	state := ctx.Query("state")
	nonce := ctx.Query("nonce")
	codeChallenge := strings.TrimSpace(ctx.Query("code_challenge"))
	codeChallengeMethod := strings.TrimSpace(ctx.Query("code_challenge_method"))

	if responseType != "code" {
		writeOAuthError(ctx, http.StatusBadRequest, "unsupported_response_type", "response_type must be code", "authorize")
		return
	}
	if clientID == "" || redirectURI == "" || state == "" {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_request", "client_id, redirect_uri, state are required", "authorize")
		return
	}
	if codeChallengeMethod != "S256" {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_request", ErrPKCEMethodNotSupported.Error(), "authorize")
		return
	}
	if codeChallenge == "" {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_request", "code_challenge is required", "authorize")
		return
	}

	client, err := h.store.GetClient(clientID)
	if err != nil || client.Status != "active" {
		writeOAuthError(ctx, http.StatusUnauthorized, "unauthorized_client", "client is invalid", "authorize")
		return
	}
	if err = ValidateRedirectURI(client, redirectURI); err != nil {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_request", ErrInvalidRedirectURI.Error(), "authorize")
		return
	}
	if err = ValidateScopes(client, scope); err != nil {
		writeOAuthError(ctx, http.StatusBadRequest, "invalid_scope", ErrInvalidRequestedScope.Error(), "authorize")
		return
	}

	user, err := h.resolveLoginUser(ctx)
	if err != nil {
		writeOAuthError(ctx, http.StatusUnauthorized, "access_denied", "user not logged in", "authorize")
		return
	}

	if client.FirstParty {
		_ = h.store.SaveConsent(ConsentRecord{
			ClientID:   client.ID,
			UserID:     user.ID,
			Scope:      scope,
			FirstParty: true,
		})
	} else {
		if existing, consentErr := h.store.GetConsent(client.ID, user.ID); consentErr == nil {
			if !scopeIsSubset(scope, existing.Scope) {
				_ = h.store.SaveConsent(ConsentRecord{
					ClientID:   client.ID,
					UserID:     user.ID,
					Scope:      mergeScopes(existing.Scope, scope),
					FirstParty: existing.FirstParty,
				})
			}
		} else {
			_ = h.store.SaveConsent(ConsentRecord{
				ClientID:   client.ID,
				UserID:     user.ID,
				Scope:      scope,
				FirstParty: false,
			})
		}
	}

	rawCode, err := randomURLSafe(32)
	if err != nil {
		writeOAuthError(ctx, http.StatusInternalServerError, "server_error", "failed to create authorization code", "authorize")
		return
	}
	now := h.nowFn()
	record := AuthCodeRecord{
		CodeHash:      sha256Hex(rawCode),
		ClientID:      client.ID,
		UserID:        user.ID,
		RedirectURI:   redirectURI,
		Scope:         scope,
		CodeChallenge: codeChallenge,
		CodeMethod:    codeChallengeMethod,
		Nonce:         nonce,
		ExpiresAt:     now.Add(h.config.AuthorizationCodeTTL),
		CreatedAt:     now,
		OriginalState: state,
	}
	if err = h.store.SaveAuthCode(record); err != nil {
		writeOAuthError(ctx, http.StatusInternalServerError, "server_error", "failed to persist authorization code", "authorize")
		return
	}
	callback, err := appendRedirectParams(redirectURI, map[string]string{
		"code":  rawCode,
		"state": state,
	})
	if err != nil {
		writeOAuthError(ctx, http.StatusInternalServerError, "server_error", "failed to render redirect", "authorize")
		return
	}
	ctx.Redirect(http.StatusFound, callback)
}

func appendRedirectParams(base string, values map[string]string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for key, value := range values {
		q.Set(key, value)
	}
	u.RawQuery = q.Encode()
	if !strings.HasPrefix(u.Scheme, "http") {
		return "", errors.New("invalid redirect uri")
	}
	return u.String(), nil
}

func MustAuthorizeURL(basePath string, client OIDCClient, redirectURI string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", client.ID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", joinScope(client.Scopes))
	q.Set("state", "state-placeholder")
	q.Set("nonce", "nonce-placeholder")
	q.Set("code_challenge", "challenge-placeholder")
	q.Set("code_challenge_method", "S256")
	return fmt.Sprintf("%s/authorize?%s", strings.TrimRight(basePath, "/"), q.Encode())
}
