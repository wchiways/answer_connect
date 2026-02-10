package oidc

import (
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
)

func ExtractAnswerUserFromContext(ctx *gin.Context) (UserProfile, bool) {
	if ctx == nil {
		return UserProfile{}, false
	}
	raw, exists := ctx.Get("ctxUuidKey")
	if !exists || raw == nil {
		return UserProfile{}, false
	}
	value := reflect.ValueOf(raw)
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return UserProfile{}, false
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return UserProfile{}, false
	}

	userID := readStructStringField(value, "UserID")
	if strings.TrimSpace(userID) == "" {
		return UserProfile{}, false
	}
	profile := UserProfile{ID: userID}
	profile.Username = readStructStringField(value, "Username")
	if profile.Username == "" {
		profile.Username = readStructStringField(value, "DisplayName")
	}
	profile.Email = readStructStringField(value, "Mail")
	profile.Name = readStructStringField(value, "DisplayName")
	if profile.Name == "" {
		profile.Name = profile.Username
	}
	return profile, true
}

func ExtractAnswerUserFromHTTPContext(ctx HTTPContext) (UserProfile, bool) {
	ginCtx, ok := ctx.(*GinContext)
	if !ok {
		return UserProfile{}, false
	}
	return ExtractAnswerUserFromContext(ginCtx.ctx)
}

func readStructStringField(value reflect.Value, fieldName string) string {
	field := value.FieldByName(fieldName)
	if !field.IsValid() || field.Kind() != reflect.String {
		return ""
	}
	return strings.TrimSpace(field.String())
}
