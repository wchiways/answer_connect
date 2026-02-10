package oidcprovider

import (
	oidc "cfszone_connect/answer_oidc_provider/internal/oidc"
	"github.com/gin-gonic/gin"
)

func extractAnswerUserFromContext(ctx *gin.Context) (oidc.UserProfile, bool) {
	return oidc.ExtractAnswerUserFromContext(ctx)
}
