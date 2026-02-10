package oidcprovider

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	oidc "cfszone_connect/answer_oidc_provider/internal/oidc"
	answerplugin "github.com/apache/answer/plugin"
	"github.com/gin-gonic/gin"
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

	users map[string]oidc.UserProfile
}

func init() {
	plugin := NewOIDCProviderPlugin()
	answerplugin.Register(plugin)
}

func NewOIDCProviderPlugin() *OIDCProviderPlugin {
	config := oidc.DefaultConfig().WithFallbackIssuer(answerplugin.SiteURL())
	instance := &OIDCProviderPlugin{
		config: config,
		users: map[string]oidc.UserProfile{
			"u_10001": {
				ID:       "u_10001",
				Username: "admin",
				Email:    "admin@example.com",
				Name:     "Answer Admin",
			},
		},
	}
	instance.rebuildServices()
	return instance
}

func (p *OIDCProviderPlugin) Info() answerplugin.Info {
	return answerplugin.Info{
		Name:        answerplugin.MakeTranslator("plugin.answer_oidc_provider.name"),
		SlugName:    pluginSlug,
		Description: answerplugin.MakeTranslator("plugin.answer_oidc_provider.description"),
		Author:      "cfszone",
		Version:     "0.2.0",
		Link:        "https://github.com/apache/answer",
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
		p.metadataHandler.HandleDiscovery(ctx)
	}))
	group.GET("/.well-known/jwks.json", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		p.metadataHandler.HandleJWKS(ctx)
	}))
	group.GET("/authorize", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		p.authorizeHandler.Handle(ctx)
	}))
	group.POST("/token", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		p.tokenHandler.Handle(ctx)
	}))
	group.GET("/userinfo", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		p.userinfoHandler.Handle(ctx)
	}))
	group.POST("/userinfo", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		p.userinfoHandler.Handle(ctx)
	}))
	group.POST("/revoke", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		p.revokeHandler.Handle(ctx)
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
		p.adminHandler.HandleList(ctx)
	}))
	group.POST("", p.wrapHTTPContext(func(ctx oidc.HTTPContext) {
		p.adminHandler.HandleCreate(ctx)
	}))
	group.GET("/:client_id", func(ctx *gin.Context) {
		p.adminHandler.HandleGet(oidc.WrapGinContext(ctx), strings.TrimSpace(ctx.Param("client_id")))
	})
	group.PUT("/:client_id", func(ctx *gin.Context) {
		p.adminHandler.HandleUpdate(oidc.WrapGinContext(ctx), strings.TrimSpace(ctx.Param("client_id")))
	})
	group.DELETE("/:client_id", func(ctx *gin.Context) {
		p.adminHandler.HandleDelete(oidc.WrapGinContext(ctx), strings.TrimSpace(ctx.Param("client_id")))
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
	if user, ok := oidc.ExtractAnswerUserFromHTTPContext(ctx); ok {
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
	if user, ok := p.users["u_10001"]; ok {
		return user, nil
	}
	return oidc.UserProfile{}, errors.New("no login user")
}

func (p *OIDCProviderPlugin) resolveUserByID(userID string) (oidc.UserProfile, error) {
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
