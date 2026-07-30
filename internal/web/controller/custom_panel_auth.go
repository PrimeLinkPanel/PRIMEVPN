package controller

import (
	"net/http"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service/panel"

	"github.com/gin-gonic/gin"
)

func customPanelAuthError(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"status":  "error",
		"message": "Invalid API Key",
	})
}

func apiTokenHasExactScope(scopes []string, required string) bool {
	required = strings.ToLower(strings.TrimSpace(required))
	if required == "" {
		return false
	}
	for _, raw := range scopes {
		if strings.ToLower(strings.TrimSpace(raw)) == required {
			return true
		}
	}
	return false
}

func (a *APIController) checkCustomPanelAuth(c *gin.Context) {
	if strings.TrimSpace(c.GetHeader("Authorization")) != "" {
		customPanelAuthError(c)
		return
	}

	apiKey := strings.TrimSpace(c.GetHeader("X-API-Key"))
	if apiKey == "" {
		customPanelAuthError(c)
		return
	}

	auth, err := a.apiTokenService.Authenticate(apiKey)
	if err != nil || auth == nil || auth.Kind != model.ApiTokenKindDelegated || auth.Subject == nil {
		customPanelAuthError(c)
		return
	}
	if !apiTokenHasExactScope(auth.Scopes, panel.ApiTokenScopeCustomPanelManage) {
		customPanelAuthError(c)
		return
	}
	if !a.setAuthenticatedAPIPrincipal(c, auth) {
		customPanelAuthError(c)
		return
	}

	c.Next()
}
