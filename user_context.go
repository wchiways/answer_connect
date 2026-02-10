package oidcprovider

import (
	"github.com/gin-gonic/gin"
	oidc "github.com/wchiways/answer_connect/internal/oidc"
)

func extractAnswerUserFromContext(ctx *gin.Context) (oidc.UserProfile, bool) {
	return oidc.ExtractAnswerUserFromContext(ctx)
}
