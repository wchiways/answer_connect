package oidc

import "github.com/gin-gonic/gin"

type GinContext struct {
	ctx *gin.Context
}

func WrapGinContext(ctx *gin.Context) HTTPContext {
	return &GinContext{ctx: ctx}
}

func (g *GinContext) Query(key string) string {
	return g.ctx.Query(key)
}

func (g *GinContext) PostForm(key string) string {
	return g.ctx.PostForm(key)
}

func (g *GinContext) Header(key string) string {
	return g.ctx.GetHeader(key)
}

func (g *GinContext) JSON(status int, value any) {
	g.ctx.JSON(status, value)
}

func (g *GinContext) Redirect(status int, location string) {
	g.ctx.Redirect(status, location)
}

func (g *GinContext) Status(status int) {
	g.ctx.Status(status)
}

func (g *GinContext) BindJSON(value any) error {
	return g.ctx.ShouldBindJSON(value)
}
