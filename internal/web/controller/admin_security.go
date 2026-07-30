package controller

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/service/panel"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/web/session"

	"github.com/gin-gonic/gin"
)

func loginActiveAdminRole(c *gin.Context) (*model.User, *model.AdminRole, bool) {
	if c.GetBool("api_authed") {
		pureJsonMsg(c, http.StatusForbidden, false, "browser session required")
		c.Abort()
		return nil, nil, false
	}

	user := session.GetLoginUser(c)
	if user == nil {
		pureJsonMsg(c, http.StatusUnauthorized, false, "login required")
		c.Abort()
		return nil, nil, false
	}

	if user.Status != "" && user.Status != model.AdminStatusActive {
		pureJsonMsg(c, http.StatusForbidden, false, "admin account is disabled")
		c.Abort()
		return nil, nil, false
	}

	db := database.GetDB()
	if db == nil {
		pureJsonMsg(c, http.StatusInternalServerError, false, "database is not initialized")
		c.Abort()
		return nil, nil, false
	}

	var role model.AdminRole
	if err := db.Where("id = ?", user.RoleId).First(&role).Error; err != nil {
		pureJsonMsg(c, http.StatusForbidden, false, "admin role not found")
		c.Abort()
		return nil, nil, false
	}

	if err := panel.EnforceLimitedAdminFeatures(user); err != nil {
		pureJsonMsg(c, http.StatusForbidden, false, err.Error())
		c.Abort()
		return nil, nil, false
	}

	return user, &role, true
}

func requireOwnerAdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, role, ok := loginActiveAdminRole(c)
		if !ok {
			return
		}

		if !role.OwnerRole {
			pureJsonMsg(c, http.StatusForbidden, false, "owner permission required")
			c.Abort()
			return
		}

		c.Next()
	}
}

func requireAdminPermission(section string, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, role, ok := loginActiveAdminRole(c)
		if !ok {
			return
		}

		if role.OwnerRole {
			c.Next()
			return
		}

		if !roleAllowsPermission(role, section, permission) {
			pureJsonMsg(c, http.StatusForbidden, false, section+"."+permission+" permission required")
			c.Abort()
			return
		}

		c.Next()
	}
}

func requirePanelPermission(section string, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetBool("api_authed") {
			c.Next()
			return
		}

		_, role, ok := loginActiveAdminRole(c)
		if !ok {
			return
		}

		if role.OwnerRole {
			c.Next()
			return
		}

		if !roleAllowsPermission(role, section, permission) {
			pureJsonMsg(c, http.StatusForbidden, false, section+"."+permission+" permission required")
			c.Abort()
			return
		}

		c.Next()
	}
}

type panelPermissionRequirement struct {
	Section    string
	Permission string
}

func roleAllowsAnyPermission(role *model.AdminRole, requirements ...panelPermissionRequirement) bool {
	if role == nil {
		return false
	}
	if role.OwnerRole {
		return true
	}
	for _, req := range requirements {
		if roleAllowsPermission(role, req.Section, req.Permission) {
			return true
		}
	}
	return false
}

func requireAnyPanelPermission(requirements ...panelPermissionRequirement) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetBool("api_authed") {
			c.Next()
			return
		}

		_, role, ok := loginActiveAdminRole(c)
		if !ok {
			return
		}

		if roleAllowsAnyPermission(role, requirements...) {
			c.Next()
			return
		}

		pureJsonMsg(c, http.StatusForbidden, false, "permission required")
		c.Abort()
	}
}

func roleAllowsPermission(role *model.AdminRole, section string, permission string) bool {
	if role == nil {
		return false
	}
	if role.OwnerRole {
		return true
	}

	root := map[string]any{}
	if err := json.Unmarshal([]byte(role.PermissionsJSON), &root); err != nil {
		return false
	}

	if rolePermissionAllowedInRoot(root, section, permission) {
		return true
	}

	return false
}

func rolePermissionAllowedInRoot(root map[string]any, section string, permission string) bool {
	for _, sectionKey := range permissionSectionKeys(section) {
		sectionValue, ok := root[sectionKey]
		if !ok {
			continue
		}

		sectionMap, ok := sectionValue.(map[string]any)
		if !ok {
			continue
		}

		for _, permissionKey := range permissionKeys(permission) {
			if permissionValueAllowed(sectionMap[permissionKey]) {
				return true
			}
		}
	}
	return false
}

func permissionSectionKeys(section string) []string {
	switch section {
	case "roles":
		return []string{"roles", "admin_roles"}
	case "admin_roles":
		return []string{"admin_roles", "roles"}
	default:
		return []string{section}
	}
}

func permissionKeys(permission string) []string {
	switch permission {
	case "view":
		return []string{"view", "read"}
	case "viewSimple":
		return []string{"viewSimple", "read_simple"}
	case "viewGeneral":
		return []string{"viewGeneral", "read_general"}
	case "resetUsage":
		return []string{"resetUsage", "reset_usage"}
	case "revokeSubscription":
		return []string{"revokeSubscription", "revoke_sub"}
	case "activateNextPlan":
		return []string{"activateNextPlan", "activate_next_plan"}
	case "setOwner":
		return []string{"setOwner", "set_owner"}
	case "updateCore":
		return []string{"updateCore", "update_core"}
	case "viewStatistics":
		return []string{"viewStatistics", "stats"}
	case "viewLogs":
		return []string{"viewLogs", "logs"}
	default:
		return []string{permission}
	}
}

func permissionValueAllowed(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "yes", "1", "own", "all":
			return true
		default:
			return false
		}
	case map[string]any:
		return permissionValueAllowed(v["scope"])
	case float64:
		return v != 0
	case int:
		return v != 0
	default:
		return false
	}
}
