package oidc

import (
	"encoding/json"
	"net/http"
	"strings"
)

type HTTPContext interface {
	Query(string) string
	PostForm(string) string
	Header(string) string
	JSON(int, any)
	Redirect(int, string)
	Status(int)
	BindJSON(any) error
}

func splitScope(scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	parts := strings.Fields(scope)
	return normalizeScopes(parts)
}

func joinScope(scopes []string) string {
	return strings.Join(normalizeScopes(scopes), " ")
}

func writeOAuthError(ctx HTTPContext, status int, errCode, description, traceID string) {
	ctx.JSON(status, OAuthError{
		Error:            errCode,
		ErrorDescription: description,
		TraceID:          traceID,
	})
}

func mustJSON(value any) string {
	b, _ := json.Marshal(value)
	return string(b)
}

func unauthorized(ctx HTTPContext, traceID string) {
	writeOAuthError(ctx, http.StatusUnauthorized, "invalid_token", "access token is invalid", traceID)
}
