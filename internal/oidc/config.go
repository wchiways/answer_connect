package oidc

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	answerplugin "github.com/apache/answer/plugin"
)

type Config struct {
	Issuer               string
	BasePath             string
	AccessTokenTTL       time.Duration
	IDTokenTTL           time.Duration
	RefreshTokenTTL      time.Duration
	AuthorizationCodeTTL time.Duration
	PrivateKeyPEM        string
	DefaultScopes        []string
}

func DefaultConfig() Config {
	return Config{
		BasePath:             "/api/auth/oidc",
		AccessTokenTTL:       10 * time.Minute,
		IDTokenTTL:           10 * time.Minute,
		RefreshTokenTTL:      30 * 24 * time.Hour,
		AuthorizationCodeTTL: 5 * time.Minute,
		DefaultScopes:        []string{"openid", "profile", "email"},
	}
}

func (c Config) normalize() Config {
	out := c
	out.Issuer = strings.TrimRight(strings.TrimSpace(out.Issuer), "/")
	if out.BasePath == "" {
		out.BasePath = "/api/auth/oidc"
	} else if !strings.HasPrefix(out.BasePath, "/") {
		out.BasePath = "/" + out.BasePath
	}
	out.BasePath = strings.TrimRight(out.BasePath, "/")
	if out.BasePath == "" {
		out.BasePath = "/api/auth/oidc"
	}
	if out.AccessTokenTTL <= 0 {
		out.AccessTokenTTL = 10 * time.Minute
	}
	if out.IDTokenTTL <= 0 {
		out.IDTokenTTL = 10 * time.Minute
	}
	if out.RefreshTokenTTL <= 0 {
		out.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if out.AuthorizationCodeTTL <= 0 {
		out.AuthorizationCodeTTL = 5 * time.Minute
	}
	if len(out.DefaultScopes) == 0 {
		out.DefaultScopes = []string{"openid", "profile", "email"}
	}
	return out
}

func (c Config) Normalize() Config {
	return c.normalize()
}

func (c Config) withFallbackIssuer(siteURL string) Config {
	out := c.normalize()
	if out.Issuer == "" {
		out.Issuer = strings.TrimRight(strings.TrimSpace(siteURL), "/")
	}
	if out.Issuer == "" {
		out.Issuer = "http://localhost:8080"
	}
	return out
}

func (c Config) WithFallbackIssuer(siteURL string) Config {
	return c.withFallbackIssuer(siteURL)
}

func (c Config) toPluginConfigFields() []answerplugin.ConfigField {
	n := c.normalize()
	return []answerplugin.ConfigField{
		{
			Name:        "issuer",
			Type:        answerplugin.ConfigTypeInput,
			Title:       answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.issuer.title"),
			Description: answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.issuer.description"),
			Required:    false,
			Value:       n.Issuer,
			UIOptions: answerplugin.ConfigFieldUIOptions{
				InputType: answerplugin.InputTypeUrl,
			},
		},
		{
			Name:        "base_path",
			Type:        answerplugin.ConfigTypeInput,
			Title:       answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.base_path.title"),
			Description: answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.base_path.description"),
			Required:    true,
			Value:       n.BasePath,
			UIOptions: answerplugin.ConfigFieldUIOptions{
				InputType: answerplugin.InputTypeText,
			},
		},
		{
			Name:        "access_token_ttl_seconds",
			Type:        answerplugin.ConfigTypeInput,
			Title:       answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.access_ttl.title"),
			Description: answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.access_ttl.description"),
			Required:    true,
			Value:       fmt.Sprintf("%d", int64(n.AccessTokenTTL/time.Second)),
			UIOptions: answerplugin.ConfigFieldUIOptions{
				InputType: answerplugin.InputTypeNumber,
			},
		},
		{
			Name:        "id_token_ttl_seconds",
			Type:        answerplugin.ConfigTypeInput,
			Title:       answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.id_ttl.title"),
			Description: answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.id_ttl.description"),
			Required:    true,
			Value:       fmt.Sprintf("%d", int64(n.IDTokenTTL/time.Second)),
			UIOptions: answerplugin.ConfigFieldUIOptions{
				InputType: answerplugin.InputTypeNumber,
			},
		},
		{
			Name:        "refresh_token_ttl_seconds",
			Type:        answerplugin.ConfigTypeInput,
			Title:       answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.refresh_ttl.title"),
			Description: answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.refresh_ttl.description"),
			Required:    true,
			Value:       fmt.Sprintf("%d", int64(n.RefreshTokenTTL/time.Second)),
			UIOptions: answerplugin.ConfigFieldUIOptions{
				InputType: answerplugin.InputTypeNumber,
			},
		},
		{
			Name:        "authorization_code_ttl_seconds",
			Type:        answerplugin.ConfigTypeInput,
			Title:       answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.code_ttl.title"),
			Description: answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.code_ttl.description"),
			Required:    true,
			Value:       fmt.Sprintf("%d", int64(n.AuthorizationCodeTTL/time.Second)),
			UIOptions: answerplugin.ConfigFieldUIOptions{
				InputType: answerplugin.InputTypeNumber,
			},
		},
		{
			Name:        "private_key_pem",
			Type:        answerplugin.ConfigTypeTextarea,
			Title:       answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.private_key.title"),
			Description: answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.private_key.description"),
			Required:    false,
			Value:       n.PrivateKeyPEM,
			UIOptions: answerplugin.ConfigFieldUIOptions{
				Rows: "8",
			},
		},
		{
			Name:        "default_scopes",
			Type:        answerplugin.ConfigTypeInput,
			Title:       answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.default_scopes.title"),
			Description: answerplugin.MakeTranslator("plugin.answer_oidc_provider.config.default_scopes.description"),
			Required:    true,
			Value:       strings.Join(n.DefaultScopes, " "),
			UIOptions: answerplugin.ConfigFieldUIOptions{
				InputType: answerplugin.InputTypeText,
			},
		},
	}
}

func (c Config) ToPluginConfigFields() []answerplugin.ConfigField {
	return c.toPluginConfigFields()
}

type configPayload struct {
	Issuer                   string `json:"issuer"`
	BasePath                 string `json:"base_path"`
	AccessTokenTTLSeconds    int64  `json:"access_token_ttl_seconds"`
	IDTokenTTLSeconds        int64  `json:"id_token_ttl_seconds"`
	RefreshTokenTTLSeconds   int64  `json:"refresh_token_ttl_seconds"`
	AuthorizationCodeTTL     int64  `json:"authorization_code_ttl_seconds"`
	PrivateKeyPEM            string `json:"private_key_pem"`
	DefaultScopesSpaceJoined string `json:"default_scopes"`
}

func parseConfig(data []byte, current Config) (Config, error) {
	next := current
	if len(data) == 0 {
		return next.withFallbackIssuer(""), nil
	}
	payload := configPayload{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return Config{}, err
	}
	if strings.TrimSpace(payload.Issuer) != "" {
		next.Issuer = payload.Issuer
	}
	if strings.TrimSpace(payload.BasePath) != "" {
		next.BasePath = payload.BasePath
	}
	if payload.AccessTokenTTLSeconds > 0 {
		next.AccessTokenTTL = time.Duration(payload.AccessTokenTTLSeconds) * time.Second
	}
	if payload.IDTokenTTLSeconds > 0 {
		next.IDTokenTTL = time.Duration(payload.IDTokenTTLSeconds) * time.Second
	}
	if payload.RefreshTokenTTLSeconds > 0 {
		next.RefreshTokenTTL = time.Duration(payload.RefreshTokenTTLSeconds) * time.Second
	}
	if payload.AuthorizationCodeTTL > 0 {
		next.AuthorizationCodeTTL = time.Duration(payload.AuthorizationCodeTTL) * time.Second
	}
	next.PrivateKeyPEM = payload.PrivateKeyPEM
	if strings.TrimSpace(payload.DefaultScopesSpaceJoined) != "" {
		next.DefaultScopes = strings.Fields(payload.DefaultScopesSpaceJoined)
	}
	return next.withFallbackIssuer(""), nil
}

func ParseConfig(data []byte, current Config) (Config, error) {
	return parseConfig(data, current)
}
