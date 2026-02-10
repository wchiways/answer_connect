package oidcprovider

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	answerplugin "github.com/apache/answer/plugin"
	"github.com/gin-gonic/gin"
	oidci18n "github.com/wchiways/answer_connect/i18n"
	oidc "github.com/wchiways/answer_connect/internal/oidc"
)

const (
	pluginSlug = "answer-oidc-provider"
)

type OIDCProviderPlugin struct {
	mu sync.RWMutex

	config oidc.Config

	store        oidc.Store
	keyService   *oidc.KeyService
	tokenService *oidc.TokenService

	authorizeHandler *oidc.AuthorizeHandler
	tokenHandler     *oidc.TokenHandler
	metadataHandler  *oidc.MetadataHandler
	userinfoHandler  *oidc.UserInfoHandler
	revokeHandler    *oidc.RevokeHandler
	adminHandler     *oidc.AdminClientHandler

	usersMu sync.RWMutex
	users   map[string]oidc.UserProfile
}

func init() {
	plugin := NewOIDCProviderPlugin()
	answerplugin.Register(plugin)
}

func NewOIDCProviderPlugin() *OIDCProviderPlugin {
	config := oidc.DefaultConfig().WithFallbackIssuer(answerplugin.SiteURL())
	instance := &OIDCProviderPlugin{
		config: config,
		users:  make(map[string]oidc.UserProfile),
	}
	instance.rebuildServices()
	return instance
}

func (p *OIDCProviderPlugin) Info() answerplugin.Info {
	return answerplugin.Info{
		Name:        answerplugin.MakeTranslator(oidci18n.PluginInfoName),
		SlugName:    pluginSlug,
		Description: answerplugin.MakeTranslator(oidci18n.PluginInfoDescription),
		Author:      "cfszone",
		Version:     "0.2.0",
		Link:        "https://github.com/wchiways/answer_connect",
	}
}

func (p *OIDCProviderPlugin) ConfigFields() []answerplugin.ConfigField {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config.ToPluginConfigFields()
}

func (p *OIDCProviderPlugin) ConfigReceiver(configBytes []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	next, err := oidc.ParseConfig(configBytes, p.config)
	if err != nil {
		return err
	}
	next = next.WithFallbackIssuer(answerplugin.SiteURL())
	p.config = next
	if err = p.rebuildServices(); err != nil {
		return err
	}
	return nil
}

func (p *OIDCProviderPlugin) RegisterUnAuthRouter(r *gin.RouterGroup) {
	if r == nil {
		return
	}
	p.mu.RLock()
	basePath := p.config.BasePath
	p.mu.RUnlock()

	group := r.Group(basePath)
	group.GET("/.well-known/openid-configuration", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		handler := p.currentMetadataHandler()
		if handler == nil {
			writeServiceUnavailable(ctx, "discovery")
			return
		}
		handler.HandleDiscovery(ctx)
	}))
	group.GET("/.well-known/jwks.json", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		handler := p.currentMetadataHandler()
		if handler == nil {
			writeServiceUnavailable(ctx, "jwks")
			return
		}
		handler.HandleJWKS(ctx)
	}))
	group.GET("/authorize", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		handler := p.currentAuthorizeHandler()
		if handler == nil {
			writeServiceUnavailable(ctx, "authorize")
			return
		}
		handler.Handle(ctx)
	}))
	group.POST("/token", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		handler := p.currentTokenHandler()
		if handler == nil {
			writeServiceUnavailable(ctx, "token")
			return
		}
		handler.Handle(ctx)
	}))
	group.GET("/userinfo", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		handler := p.currentUserInfoHandler()
		if handler == nil {
			writeServiceUnavailable(ctx, "userinfo")
			return
		}
		handler.Handle(ctx)
	}))
	group.POST("/userinfo", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		handler := p.currentUserInfoHandler()
		if handler == nil {
			writeServiceUnavailable(ctx, "userinfo")
			return
		}
		handler.Handle(ctx)
	}))
	group.POST("/revoke", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		handler := p.currentRevokeHandler()
		if handler == nil {
			writeServiceUnavailable(ctx, "revoke")
			return
		}
		handler.Handle(ctx)
	}))
}

func (p *OIDCProviderPlugin) RegisterAuthUserRouter(r *gin.RouterGroup) {
	if r == nil {
		return
	}
}

func (p *OIDCProviderPlugin) RegisterAuthAdminRouter(r *gin.RouterGroup) {
	if r == nil {
		return
	}
	p.mu.RLock()
	basePath := p.config.BasePath
	p.mu.RUnlock()
	group := r.Group(basePath + "/admin/clients")
	group.GET("", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		handler := p.currentAdminHandler()
		if handler == nil {
			writeServiceUnavailable(ctx, "admin_client_list")
			return
		}
		handler.HandleList(ctx)
	}))
	group.POST("", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		handler := p.currentAdminHandler()
		if handler == nil {
			writeServiceUnavailable(ctx, "admin_client_create")
			return
		}
		handler.HandleCreate(ctx)
	}))
	group.GET("/:client_id", func(ctx *gin.Context) {
		handler := p.currentAdminHandler()
		if handler == nil {
			ctx.JSON(http.StatusInternalServerError, oidc.OAuthError{Error: "server_error", ErrorDescription: "service unavailable", TraceID: "admin_client_get"})
			return
		}
		handler.HandleGet(oidc.WrapGinContext(ctx), strings.TrimSpace(ctx.Param("client_id")))
	})
	group.PUT("/:client_id", func(ctx *gin.Context) {
		handler := p.currentAdminHandler()
		if handler == nil {
			ctx.JSON(http.StatusInternalServerError, oidc.OAuthError{Error: "server_error", ErrorDescription: "service unavailable", TraceID: "admin_client_update"})
			return
		}
		handler.HandleUpdate(oidc.WrapGinContext(ctx), strings.TrimSpace(ctx.Param("client_id")))
	})
	group.DELETE("/:client_id", func(ctx *gin.Context) {
		handler := p.currentAdminHandler()
		if handler == nil {
			ctx.JSON(http.StatusInternalServerError, oidc.OAuthError{Error: "server_error", ErrorDescription: "service unavailable", TraceID: "admin_client_delete"})
			return
		}
		handler.HandleDelete(oidc.WrapGinContext(ctx), strings.TrimSpace(ctx.Param("client_id")))
	})
}

func (p *OIDCProviderPlugin) SetOperator(operator *answerplugin.KVOperator) {
	if operator == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.store = oidc.NewKVStore(operator)
	_ = p.rebuildServices()
}

func (p *OIDCProviderPlugin) rebuildServices() error {
	keyService, err := oidc.NewKeyService(p.config.PrivateKeyPEM)
	if err != nil {
		return err
	}
	if p.store == nil {
		p.store = oidc.NewInMemoryStore()
	}
	p.keyService = keyService
	p.tokenService = oidc.NewTokenService(p.config, keyService)
	p.authorizeHandler = oidc.NewAuthorizeHandler(p.store, p.config, p.resolveCurrentUser)
	p.tokenHandler = oidc.NewTokenHandler(p.store, p.tokenService)
	p.metadataHandler = oidc.NewMetadataHandler(p.config, p.keyService)
	p.userinfoHandler = oidc.NewUserInfoHandler(p.tokenService, p.resolveUserByID)
	p.revokeHandler = oidc.NewRevokeHandler(p.store)
	p.adminHandler = oidc.NewAdminClientHandler(p.store)
	return nil
}

func (p *OIDCProviderPlugin) resolveCurrentUser(ctx oidc.HTTPContext) (oidc.UserProfile, error) {
	user, ok := oidc.ExtractAnswerUserFromHTTPContext(ctx)
	if !ok {
		return oidc.UserProfile{}, errors.New("no login user")
	}

	p.usersMu.Lock()
	defer p.usersMu.Unlock()
	if existing, hit := p.users[user.ID]; hit {
		if user.Username == "" {
			user.Username = existing.Username
		}
		if user.Email == "" {
			user.Email = existing.Email
		}
		if user.Name == "" {
			user.Name = existing.Name
		}
	}
	if user.Username == "" {
		user.Username = user.ID
	}
	if user.Name == "" {
		user.Name = user.Username
	}
	p.users[user.ID] = user
	return user, nil
}

func (p *OIDCProviderPlugin) resolveUserByID(userID string) (oidc.UserProfile, error) {
	p.usersMu.RLock()
	defer p.usersMu.RUnlock()
	user, ok := p.users[userID]
	if !ok {
		return oidc.UserProfile{}, errors.New("user not found")
	}
	return user, nil
}

func (p *OIDCProviderPlugin) wrapHTTPContext(handler func(ctx oidc.HTTPContext)) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		handler(oidc.WrapGinContext(ctx))
	}
}

func (p *OIDCProviderPlugin) DebugSnapshot() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	b, _ := json.MarshalIndent(map[string]any{
		"info":   p.Info(),
		"config": p.config,
	}, "", "  ")
	return string(b)
}

func (p *OIDCProviderPlugin) HealthHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, map[string]any{"status": "ok", "plugin": pluginSlug})
	}
}

func (p *OIDCProviderPlugin) currentAuthorizeHandler() *oidc.AuthorizeHandler {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.authorizeHandler
}

func (p *OIDCProviderPlugin) currentTokenHandler() *oidc.TokenHandler {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.tokenHandler
}

func (p *OIDCProviderPlugin) currentMetadataHandler() *oidc.MetadataHandler {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.metadataHandler
}

func (p *OIDCProviderPlugin) currentUserInfoHandler() *oidc.UserInfoHandler {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.userinfoHandler
}

func (p *OIDCProviderPlugin) currentRevokeHandler() *oidc.RevokeHandler {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.revokeHandler
}

func (p *OIDCProviderPlugin) currentAdminHandler() *oidc.AdminClientHandler {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.adminHandler
}

func writeServiceUnavailable(ctx oidc.HTTPContext, traceID string) {
	ctx.JSON(http.StatusInternalServerError, oidc.OAuthError{
		Error:            "server_error",
		ErrorDescription: "service unavailable",
		TraceID:          traceID,
	})
}
