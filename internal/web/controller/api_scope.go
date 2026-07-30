package controller

import (
	"net/http"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service/panel"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/session"

	"github.com/gin-gonic/gin"
)

// delegatedAPIRouteScope is intentionally an explicit allowlist. Browser
// sessions retain their RBAC-controlled panel behavior, while trusted service
// tokens and mTLS retain their legacy full API contract. Delegated tokens are
// denied everywhere unless a route is reviewed and assigned a scope here.
func delegatedAPIRouteScope(method string, fullPath string) (string, bool) {
	switch method {
	case http.MethodGet:
		switch fullPath {
		case "/panel/api/clients/list",
			"/panel/api/clients/list/paged",
			"/panel/api/clients/get/:email",
			"/panel/api/clients/traffic/:email",
			"/panel/api/clients/subLinks/:subId",
			"/panel/api/clients/links/:email",
			"/panel/api/clients/:email/activity",
			"/panel/api/clients/:email/activity/status":
			return panel.ApiTokenScopeClientsRead, true
		}
	case http.MethodPost:
		switch fullPath {
		case "/panel/api/clients/add",
			"/panel/api/clients/bulkCreate":
			return panel.ApiTokenScopeClientsCreate, true
		}
	}
	return "", false
}

func canonicalPanelAPIPath(fullPath string) (string, bool) {
	// The panel may be mounted below a randomized web base path. Gin FullPath
	// includes that prefix, so scope policy must compare the stable API suffix
	// rather than assuming /panel/api starts at byte zero.
	const marker = "/panel/api/"
	index := strings.LastIndex(fullPath, marker)
	if index < 0 {
		return "", false
	}
	return fullPath[index:], true
}

func enforceDelegatedAPIScope() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Browser sessions have no API principal and continue into the existing
		// dashboard RBAC. Service and mTLS principals deliberately preserve the
		// full-panel integration contract used by remote nodes.
		if !c.GetBool("api_authed") || session.IsServiceAPIAuth(c) {
			c.Next()
			return
		}

		// An authenticated API request with an unknown principal kind must fail
		// closed. checkAPIAuth currently creates only service, mTLS, or delegated
		// principals, but this guard protects future authentication changes too.
		if !session.IsDelegatedAPIAuth(c) {
			pureJsonMsg(c, http.StatusForbidden, false, "API token principal is not permitted")
			c.Abort()
			return
		}

		apiPath, canonical := canonicalPanelAPIPath(c.FullPath())
		required, routeAllowed := delegatedAPIRouteScope(c.Request.Method, apiPath)
		if !canonical || !routeAllowed || !session.APIAuthScopeAllowed(c, required) {
			pureJsonMsg(c, http.StatusForbidden, false, "API token scope does not allow this operation")
			c.Abort()
			return
		}

		c.Next()
	}
}
