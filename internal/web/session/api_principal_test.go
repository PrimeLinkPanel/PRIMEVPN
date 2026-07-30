package session

import (
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

func TestAPIAuthPrincipalCopiesScopesAndMatchesSafely(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(nil)
	user := &model.User{Id: 7, Username: "operator"}
	scopes := []string{"clients:read"}
	SetAPIAuthPrincipal(ctx, user, &APIAuthPrincipal{
		TokenId: 11,
		Kind:    model.ApiTokenKindDelegated,
		Scopes:  scopes,
	})
	scopes[0] = "*"

	if !IsDelegatedAPIAuth(ctx) || IsServiceAPIAuth(ctx) {
		t.Fatalf("unexpected principal classification: %#v", GetAPIAuthPrincipal(ctx))
	}
	if !APIAuthScopeAllowed(ctx, "clients:read") {
		t.Fatal("exact delegated scope was not accepted")
	}
	if APIAuthScopeAllowed(ctx, "clients:create") || APIAuthScopeAllowed(ctx, "settings:update") {
		t.Fatal("ungranted delegated scope was accepted")
	}
	if got := GetLoginUser(ctx); got == nil || got.Id != user.Id {
		t.Fatalf("API auth user = %#v, want id %d", got, user.Id)
	}
}

func TestAPIAuthPrincipalServiceWildcard(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(nil)
	SetAPIAuthUser(ctx, &model.User{Id: 1})
	if !IsServiceAPIAuth(ctx) || IsDelegatedAPIAuth(ctx) {
		t.Fatalf("unexpected service principal classification: %#v", GetAPIAuthPrincipal(ctx))
	}
	if !APIAuthScopeAllowed(ctx, "settings:update") {
		t.Fatal("service wildcard did not allow requested scope")
	}
}
