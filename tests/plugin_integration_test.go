package oidcprovider_test

import (
	"encoding/json"
	"fmt"
	"testing"

	oidcprovider "cfszone_connect/answer_oidc_provider"
	answerplugin "github.com/apache/answer/plugin"
	"github.com/gin-gonic/gin"
)

func TestPluginImplementsAnswerInterfaces(t *testing.T) {
	instance := oidcprovider.NewOIDCProviderPlugin()

	if _, ok := any(instance).(answerplugin.Base); !ok {
		t.Fatalf("plugin should implement plugin.Base")
	}
	if _, ok := any(instance).(answerplugin.Config); !ok {
		t.Fatalf("plugin should implement plugin.Config")
	}
	if _, ok := any(instance).(answerplugin.Agent); !ok {
		t.Fatalf("plugin should implement plugin.Agent")
	}
	if _, ok := any(instance).(answerplugin.KVStorage); !ok {
		t.Fatalf("plugin should implement plugin.KVStorage")
	}
}

func TestConfigReceiverUpdatesConfig(t *testing.T) {
	instance := oidcprovider.NewOIDCProviderPlugin()
	payload := map[string]any{
		"issuer":                         "https://sso.example.com",
		"base_path":                      "/answer/oidc",
		"access_token_ttl_seconds":       120,
		"id_token_ttl_seconds":           180,
		"refresh_token_ttl_seconds":      3600,
		"authorization_code_ttl_seconds": 300,
		"default_scopes":                 "openid profile email",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if err = instance.ConfigReceiver(raw); err != nil {
		t.Fatalf("config receiver error: %v", err)
	}

	fields := instance.ConfigFields()
	issuer, ok := getFieldValue(fields, "issuer")
	if !ok {
		t.Fatalf("missing issuer config field")
	}
	if issuer != "https://sso.example.com" {
		t.Fatalf("issuer not updated: %s", issuer)
	}

	basePath, ok := getFieldValue(fields, "base_path")
	if !ok {
		t.Fatalf("missing base_path config field")
	}
	if basePath != "/answer/oidc" {
		t.Fatalf("base path not updated: %s", basePath)
	}
}

func TestRouteRegistration(t *testing.T) {
	instance := oidcprovider.NewOIDCProviderPlugin()
	engine := gin.New()
	apiV1 := engine.Group("/answer/api/v1")
	adminAPI := engine.Group("/answer/admin/api")

	instance.RegisterUnAuthRouter(apiV1)
	instance.RegisterAuthAdminRouter(adminAPI)

	allRoutes := engine.Routes()
	if len(allRoutes) == 0 {
		t.Fatalf("expected routes to be registered")
	}
}

func getFieldValue(fields []answerplugin.ConfigField, name string) (string, bool) {
	for _, field := range fields {
		if field.Name == name {
			return fmt.Sprint(field.Value), true
		}
	}
	return "", false
}
