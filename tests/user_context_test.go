package oidcprovider_test

import (
	"testing"

	"github.com/gin-gonic/gin"
	oidc "github.com/wchiways/answer_connect/internal/oidc"
)

type fakeAnswerUser struct {
	UserID      string
	Username    string
	DisplayName string
	Mail        string
}

func TestExtractAnswerUserFromContext(t *testing.T) {
	ctx, _ := gin.CreateTestContext(nil)
	ctx.Set("ctxUuidKey", &fakeAnswerUser{
		UserID:      "u_200",
		Username:    "john",
		DisplayName: "John Doe",
		Mail:        "john@example.com",
	})

	user, ok := oidc.ExtractAnswerUserFromContext(ctx)
	if !ok {
		t.Fatalf("expected user to be extracted")
	}
	if user.ID != "u_200" {
		t.Fatalf("unexpected user id: %s", user.ID)
	}
	if user.Username != "john" {
		t.Fatalf("unexpected username: %s", user.Username)
	}
}

func TestExtractAnswerUserFromHTTPContext(t *testing.T) {
	ctx, _ := gin.CreateTestContext(nil)
	ctx.Set("ctxUuidKey", &fakeAnswerUser{
		UserID:      "u_300",
		DisplayName: "Alice",
		Mail:        "alice@example.com",
	})

	user, ok := oidc.ExtractAnswerUserFromHTTPContext(oidc.WrapGinContext(ctx))
	if !ok {
		t.Fatalf("expected user to be extracted from HTTP context")
	}
	if user.ID != "u_300" {
		t.Fatalf("unexpected user id: %s", user.ID)
	}
	if user.Username == "" {
		t.Fatalf("expected username fallback to be set")
	}
}
