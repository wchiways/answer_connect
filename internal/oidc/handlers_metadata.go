package oidc

import (
	"fmt"
	"net/http"
	"strings"
)

type MetadataHandler struct {
	config     Config
	keyService *KeyService
}

func NewMetadataHandler(config Config, keyService *KeyService) *MetadataHandler {
	return &MetadataHandler{
		config:     config.normalize(),
		keyService: keyService,
	}
}

func (h *MetadataHandler) HandleDiscovery(ctx HTTPContext) {
	base := strings.TrimRight(h.config.BasePath, "/")
	ctx.JSON(http.StatusOK, map[string]any{
		"issuer":                                h.config.Issuer,
		"authorization_endpoint":                fmt.Sprintf("%s%s/authorize", h.config.Issuer, base),
		"token_endpoint":                        fmt.Sprintf("%s%s/token", h.config.Issuer, base),
		"userinfo_endpoint":                     fmt.Sprintf("%s%s/userinfo", h.config.Issuer, base),
		"jwks_uri":                              fmt.Sprintf("%s%s/.well-known/jwks.json", h.config.Issuer, base),
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"scopes_supported":                      h.config.DefaultScopes,
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"revocation_endpoint":                   fmt.Sprintf("%s%s/revoke", h.config.Issuer, base),
	})
}

func (h *MetadataHandler) HandleJWKS(ctx HTTPContext) {
	ctx.JSON(http.StatusOK, h.keyService.JWKS())
}
